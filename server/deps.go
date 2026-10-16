package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/zyfanlyb/util/common"
)

// ---------------------------------------------------------------------------
// 接入说明
//
// 1. 实现 UserProvider、ClientProvider；传入已有 *redis.Client 与 *gin.Engine
// 2. 按需用环境变量配置 Issuer、密钥轮换等（见 Config 字段注释）
// 3. 调用 New(Dependencies) 创建服务（内部读环境变量并挂载 OAuth 路由）
// 4. 业务逻辑里需要鉴权时，调用 export.go 中的开放方法
//
// 本包已托管：登录页、同意页、会话、授权码、令牌、RS256 密钥对（均走 Redis）
// 标准授权码流程：客户端 → GET /oauth/authorize →（未登录）/oauth/login →（已登录）同意页
//                  → POST /oauth/consent → redirect_uri?code=...
// ---------------------------------------------------------------------------

// Dependencies 业务系统接入时需要注入的依赖。
type Dependencies struct {
	// Users 【必须实现】校验账号密码、按用户 ID(sub) 查用户资料
	Users UserProvider

	// Clients 【必须实现】查询 OAuth 客户端、校验 client_secret
	Clients ClientProvider

	// Redis 【必须提供】业务系统已有的 go-redis 客户端，例如全局 var RedisDB *redis.Client
	Redis *redis.Client

	// Engine 【必须提供】业务系统已有的 gin 引擎；New 时自动挂载 OAuth / OIDC 路由
	Engine *gin.Engine
}

// New 创建授权服务器。Config 从环境变量读取；会校验必填依赖、初始化密钥，并向 Engine 挂载路由。
func New(dep Dependencies) (*Server, error) {
	cfg := configFromEnv()
	if dep.Users == nil {
		return nil, errors.New("Dependencies.Users 不能为空：请实现 UserProvider（登录校验 / 查用户）")
	}
	if dep.Clients == nil {
		return nil, errors.New("Dependencies.Clients 不能为空：请实现 ClientProvider（客户端查询 / 校验密钥）")
	}
	if dep.Redis == nil {
		return nil, errors.New("Dependencies.Redis 不能为空：请传入业务系统的 *redis.Client")
	}
	if dep.Engine == nil {
		return nil, errors.New("Dependencies.Engine 不能为空：请传入业务系统的 *gin.Engine")
	}
	if cfg.Issuer == "" {
		return nil, errors.New("Config.Issuer 不能为空：例如 https://auth.example.com")
	}

	s := &Server{
		Config:  cfg,
		Users:   dep.Users,
		Clients: dep.Clients,
		Redis:   dep.Redis,
	}
	s.initStores()
	if err := s.ensureKeys(context.Background()); err != nil {
		return nil, fmt.Errorf("初始化 RS256 密钥失败: %w", err)
	}
	s.registerRoutes(dep.Engine)
	return s, nil
}

// ========================= 必须由业务系统实现 =========================

// UserProvider 用户数据源。登录页由本包提供，这里只负责“账密对不对 / 用户是谁”。
type UserProvider interface {
	// Authenticate 校验用户名密码；失败返回 (nil, error)
	Authenticate(ctx context.Context, username, password string) (*UserClaims, error)
	// FindBySubject 按 sub 加载用户（userinfo、签发 id_token 时用）
	FindBySubject(ctx context.Context, sub string) (*UserClaims, error)
}

// ClientProvider OAuth 客户端数据源（哪些应用允许接入）。
type ClientProvider interface {
	// Get 按 client_id 查询客户端
	Get(ctx context.Context, clientID string) (*Client, error)
	// Authenticate 校验 client_id + client_secret；公开客户端 secret 可为空
	Authenticate(ctx context.Context, clientID, clientSecret string) (*Client, error)
}

// ========================= 配置与模型 =========================

// Config 授权服务器配置。由 configFromEnv 从环境变量填充；空值走 withDefaults。Issuer 必须配置。
type Config struct {
	// Issuer 签发者，例如 https://auth.example.com（必填）。环境变量 ISSUER
	Issuer string
	// AuthCodeTTL 授权码有效期，默认 10 分钟。环境变量 AUTH_CODE_TTL
	AuthCodeTTL time.Duration
	// AccessTokenTTL 访问令牌有效期，默认 1 小时。环境变量 ACCESS_TOKEN_TTL
	AccessTokenTTL time.Duration
	// RefreshTokenTTL 刷新令牌有效期，默认 30 天。环境变量 REFRESH_TOKEN_TTL
	RefreshTokenTTL time.Duration
	// SessionTTL 登录会话有效期，默认 24 小时。环境变量 SESSION_TTL
	SessionTTL time.Duration
	// SessionCookie Cookie 名，默认 oauth_session。环境变量 SESSION_COOKIE
	SessionCookie string
	// CookieSecure 是否仅 HTTPS 传 Cookie。环境变量 COOKIE_SECURE=true
	CookieSecure bool
	// RedisKeyPrefix Redis 键前缀，默认 oauth。环境变量 SERVER_REDIS_KEY_PREFIX
	RedisKeyPrefix string
	// RequirePKCE 是否强制 PKCE。环境变量 REQUIRE_PKCE=true
	RequirePKCE bool
	// LoginPath 登录页路径（由 New 挂路由时固定为 /oauth/login，一般无需配置）
	LoginPath string
	// ConsentPath 同意授权页提交路径（由 New 挂路由时固定为 /oauth/consent）
	ConsentPath string
	// KeyRotateEvery 密钥轮换周期，默认 30 天；设为负数关闭自动轮换。环境变量 KEY_ROTATE_EVERY
	KeyRotateEvery time.Duration
	// KeyRetainFor 旧密钥在 JWKS 中保留时长，默认 7 天。环境变量 KEY_RETAIN_FOR
	KeyRetainFor time.Duration
}

func configFromEnv() Config {
	return Config{
		Issuer:          strings.TrimSpace(os.Getenv("ISSUER")),
		AuthCodeTTL:     common.StringToDuration(strings.TrimSpace(os.Getenv("AUTH_CODE_TTL"))),
		AccessTokenTTL:  common.StringToDuration(strings.TrimSpace(os.Getenv("ACCESS_TOKEN_TTL"))),
		RefreshTokenTTL: common.StringToDuration(strings.TrimSpace(os.Getenv("REFRESH_TOKEN_TTL"))),
		SessionTTL:      common.StringToDuration(strings.TrimSpace(os.Getenv("SESSION_TTL"))),
		SessionCookie:   strings.TrimSpace(os.Getenv("SESSION_COOKIE")),
		CookieSecure:    strings.TrimSpace(os.Getenv("COOKIE_SECURE")) == "true",
		RedisKeyPrefix:  strings.TrimSpace(os.Getenv("SERVER_REDIS_KEY_PREFIX")),
		RequirePKCE:     strings.TrimSpace(os.Getenv("REQUIRE_PKCE")) == "true",
		KeyRotateEvery:  common.StringToDuration(strings.TrimSpace(os.Getenv("KEY_ROTATE_EVERY"))),
		KeyRetainFor:    common.StringToDuration(strings.TrimSpace(os.Getenv("KEY_RETAIN_FOR"))),
	}
}

func (c *Config) withDefaults() Config {
	out := *c
	if out.AuthCodeTTL == 0 {
		out.AuthCodeTTL = 10 * time.Minute
	}
	if out.AccessTokenTTL == 0 {
		out.AccessTokenTTL = time.Hour
	}
	if out.RefreshTokenTTL == 0 {
		out.RefreshTokenTTL = 30 * 24 * time.Hour
	}
	if out.SessionTTL == 0 {
		out.SessionTTL = 24 * time.Hour
	}
	if out.SessionCookie == "" {
		out.SessionCookie = "oauth_session"
	}
	if out.RedisKeyPrefix == "" {
		out.RedisKeyPrefix = "oauth"
	}
	if out.LoginPath == "" {
		out.LoginPath = "/oauth/login"
	}
	if out.ConsentPath == "" {
		out.ConsentPath = "/oauth/consent"
	}
	if out.KeyRotateEvery == 0 {
		out.KeyRotateEvery = 30 * 24 * time.Hour
	}
	if out.KeyRetainFor == 0 {
		out.KeyRetainFor = 7 * 24 * time.Hour
	}
	return out
}

// UserClaims 用户身份声明（OIDC 常用字段）。
type UserClaims struct {
	Subject       string         // sub，必填
	Name          string         // name
	Email         string         // email
	EmailVerified bool           // email_verified
	Extra         map[string]any // 额外声明
}

// Client 已注册的 OAuth 客户端。
type Client struct {
	ID           string
	RedirectURIs []string
	GrantTypes   []string // 空则默认 authorization_code, refresh_token；client_credentials 须显式声明
	Scopes       []string // 空表示不限制
	Confidential bool     // true=机密客户端，换 token 需 secret
}

// ========================= 本包内部模型（业务一般不用实现） =========================

// AuthCode 授权码。
type AuthCode struct {
	Code                string
	ClientID            string
	RedirectURI         string
	Subject             string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
}

// AccessToken 访问令牌元数据。RefreshToken 只存在服务端记录里，不写入 JWT。
type AccessToken struct {
	Token        string
	ClientID     string
	Subject      string
	Scope        string
	RefreshToken string
	ExpiresAt    time.Time
}

// RefreshToken 刷新令牌。
type RefreshToken struct {
	Token     string
	ClientID  string
	Subject   string
	Scope     string
	ExpiresAt time.Time
}

// CodeStore / TokenStore 由本包基于 Redis 自动实现，业务无需实现。
type CodeStore interface {
	Save(ctx context.Context, code *AuthCode) error
	Take(ctx context.Context, code string) (*AuthCode, error)
}

type TokenStore interface {
	SaveAccess(ctx context.Context, t *AccessToken) error
	SaveRefresh(ctx context.Context, t *RefreshToken) error
	GetAccess(ctx context.Context, token string) (*AccessToken, error)
	GetRefresh(ctx context.Context, token string) (*RefreshToken, error)
	RevokeAccess(ctx context.Context, token string) error
	RevokeRefresh(ctx context.Context, token string) error
}

// Server 授权服务器实例。请通过 New 创建，不要手填未导出字段。
type Server struct {
	Config  Config
	Users   UserProvider
	Clients ClientProvider
	Redis   *redis.Client

	Codes  CodeStore
	Tokens TokenStore

	sessions *sessionStore
	keyMu    sync.RWMutex
	keyCache *keyBundle
}

func (s *Server) initStores() {
	s.Config = s.Config.withDefaults()
	if s.Redis == nil {
		return
	}
	p := s.Config.RedisKeyPrefix
	if s.Codes == nil {
		s.Codes = newCodeStore(s.Redis, p)
	}
	if s.Tokens == nil {
		s.Tokens = newTokenStore(s.Redis, p)
	}
	s.sessions = newSessionStore(s.Redis, p, s.Config.SessionTTL)
}
