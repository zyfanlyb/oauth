package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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
// 1. 用环境变量配置 Host / Port、ClientID、RedirectURI 等（见 Config 字段注释）；传入 *redis.Client 与 *gin.Engine
// 2. 调用 New(Dependencies) 创建客户端（内部读环境变量，按 Host/Port 向认证中心发 HTTP）
// 3. 浏览器登录：New 在 RedirectURI 同级挂 GET .../login（如 /auth/login），访问后 302 到授权中心；回调由本包挂在 RedirectURI 上并内部换票
//    客户端凭证：ClientCredentials(ctx, scope)，有缓存则直接返回
// 4. 接口鉴权：开启 EnableAuthMiddleware 时自动挂中间件；也可自行调用 VerifyAccessToken。业务里用 CurrentPrincipal(c) 取当前用户。REALTIME_VERIFY=true 时只请求 /oauth/introspect
// ---------------------------------------------------------------------------

// Dependencies 依赖方接入时需要注入的依赖。
type Dependencies struct {
	// Redis 【必须提供】业务系统已有的 go-redis 客户端。
	// 用于：授权流程 state（及可选 PKCE/nonce）暂存、JWKS 强制刷新冷却。
	Redis *redis.Client

	// Engine 【必须提供】业务系统已有的 gin 引擎；
	// EnableAuthMiddleware 开启时，New 内自动挂载鉴权中间件。
	Engine *gin.Engine
}

// Config 客户端配置。由 configFromEnv 从环境变量填充。
type Config struct {
	// Host 授权服务器 IP 或域名，例如 127.0.0.1 或 auth.example.com（必填）。环境变量 OAUTH_SERVER_HOST
	Host string
	// Port 授权服务器端口；0 表示不写端口（用 80/443 默认端口）。环境变量 OAUTH_SERVER_PORT
	Port int
	// TLS 是否使用 https。环境变量 OAUTH_SERVER_TLS=true
	TLS bool
	// ClientID 客户端标识（必填）；验签时也会校验 JWT 的 aud。环境变量 CLIENT_ID
	ClientID string
	// ClientSecret 客户端密钥；公开客户端可为空。环境变量 CLIENT_SECRET
	ClientSecret string
	// RedirectURI 授权回调地址，须与注册时一致。环境变量 REDIRECT_URI
	RedirectURI string
	// Scopes 默认申请的权限范围，空格分隔，例如 "openid profile email"。环境变量 SCOPES
	Scopes string
	// Issuer 可选；本地验签时默认用此值校验 iss。空则用 BaseURL。环境变量 ISSUER。
	// 须与认证中心 Issuer 一致（若认证中心 Issuer 不是 Host:Port 形式，务必填写）。
	Issuer string
	// JWKSCacheTTL 内存中公钥缓存时长，默认 1 小时；设为负数关闭内存缓存。环境变量 JWKSCACHE_TTL
	JWKSCacheTTL time.Duration
	// JWKSRefreshCooldown kid 未命中触发强制刷新 JWKS 的冷却时间，默认 5 分钟。环境变量 JWKSREFRESH_COOLDOWN。
	// 刷新成功（或已占用冷却）期间写入 Redis，避免恶意刷公钥。
	JWKSRefreshCooldown time.Duration
	// RedisKeyPrefix Redis 键前缀，默认 oauth_client。环境变量 CLIENT_REDIS_KEY_PREFIX
	RedisKeyPrefix string
	// AuthRequestTTL 授权中间态（state / PKCE / nonce）在 Redis 中的有效期，默认 10 分钟。环境变量 AUTH_REQUEST_TTL
	AuthRequestTTL time.Duration
	// UsePKCE 为 true 时本包自动生成 PKCE 并参与换票；未开启则不带 code_challenge。环境变量 USE_PKCE=true
	UsePKCE bool
	// UseNonce 为 true 时本包自动生成 nonce（OIDC），换票后校验 id_token.nonce。环境变量 USE_NONCE=true
	UseNonce bool
	// RealtimeVerify 为 true 时只请求 /oauth/introspect，由授权中心验签并确认未撤销。
	// 为 false 时只做本地验签。需要 ClientSecret。环境变量 REALTIME_VERIFY=true
	RealtimeVerify bool

	// EnableAuthMiddleware 为 true 时开启鉴权中间件。环境变量 ENABLE_AUTH_MIDDLEWARE=true
	EnableAuthMiddleware bool
	// AuthWhitelist 白名单路径：不鉴权。精确匹配，或以 /* 结尾表示前缀，例如 /health、/callback/*。
	// 环境变量 AUTH_WHITELIST，逗号分隔。
	AuthWhitelist []string
	// AuthBlacklist 黑名单路径：必须鉴权。环境变量 AUTH_BLACKLIST，逗号分隔。
	// 为空：除白名单外全部鉴权；非空：仅黑名单内路径鉴权（白名单优先于黑名单）。
	AuthBlacklist []string
}

func configFromEnv() Config {
	return Config{
		Host:                 strings.TrimSpace(os.Getenv("OAUTH_SERVER_HOST")),
		Port:                 common.StringToInt(strings.TrimSpace(os.Getenv("OAUTH_SERVER_PORT"))),
		TLS:                  strings.TrimSpace(os.Getenv("OAUTH_SERVER_TLS")) == "true",
		ClientID:             strings.TrimSpace(os.Getenv("CLIENT_ID")),
		ClientSecret:         strings.TrimSpace(os.Getenv("CLIENT_SECRET")),
		RedirectURI:          strings.TrimSpace(os.Getenv("REDIRECT_URI")),
		Scopes:               strings.TrimSpace(os.Getenv("SCOPES")),
		Issuer:               strings.TrimSpace(os.Getenv("ISSUER")),
		JWKSCacheTTL:         common.StringToDuration(strings.TrimSpace(os.Getenv("JWKSCACHE_TTL"))),
		JWKSRefreshCooldown:  common.StringToDuration(strings.TrimSpace(os.Getenv("JWKSREFRESH_COOLDOWN"))),
		RedisKeyPrefix:       strings.TrimSpace(os.Getenv("CLIENT_REDIS_KEY_PREFIX")),
		AuthRequestTTL:       common.StringToDuration(strings.TrimSpace(os.Getenv("AUTH_REQUEST_TTL"))),
		UsePKCE:              strings.TrimSpace(os.Getenv("USE_PKCE")) == "true",
		UseNonce:             strings.TrimSpace(os.Getenv("USE_NONCE")) == "true",
		RealtimeVerify:       strings.TrimSpace(os.Getenv("REALTIME_VERIFY")) == "true",
		EnableAuthMiddleware: strings.TrimSpace(os.Getenv("ENABLE_AUTH_MIDDLEWARE")) == "true",
		AuthWhitelist:        splitCSV(os.Getenv("AUTH_WHITELIST")),
		AuthBlacklist:        splitCSV(os.Getenv("AUTH_BLACKLIST")),
	}
}

func splitCSV(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Client OAuth / OIDC 依赖方客户端。请通过 New 创建。
type Client struct {
	Config     Config
	Redis      *redis.Client
	baseURL    string
	httpClient *http.Client

	jwksMu    sync.RWMutex
	jwks      common.JWKS
	jwksUntil time.Time
}

// New 创建 OAuth 客户端。Config 从环境变量读取；Host、ClientID、Redis、Engine 必填。
// EnableAuthMiddleware 开启时自动向 Engine 挂载鉴权中间件。
func New(dep Dependencies) (*Client, error) {
	cfg := configFromEnv()
	if cfg.Host == "" {
		return nil, errors.New("Config.Host 不能为空")
	}
	if cfg.ClientID == "" {
		return nil, errors.New("Config.ClientID 不能为空")
	}
	if cfg.RealtimeVerify && cfg.ClientSecret == "" {
		return nil, errors.New("RealtimeVerify 需要 ClientSecret：/oauth/introspect 要校验客户端凭证")
	}
	if dep.Redis == nil {
		return nil, errors.New("Dependencies.Redis 不能为空：请传入业务系统的 *redis.Client")
	}
	if dep.Engine == nil {
		return nil, errors.New("Dependencies.Engine 不能为空：请传入业务系统的 *gin.Engine")
	}
	if cfg.JWKSCacheTTL == 0 {
		cfg.JWKSCacheTTL = time.Hour
	}
	if cfg.JWKSRefreshCooldown == 0 {
		cfg.JWKSRefreshCooldown = 5 * time.Minute
	}
	if cfg.RedisKeyPrefix == "" {
		cfg.RedisKeyPrefix = "oauth_client"
	}
	if cfg.AuthRequestTTL == 0 {
		cfg.AuthRequestTTL = 10 * time.Minute
	}
	scheme := "http"
	if cfg.TLS {
		scheme = "https"
	}
	host := cfg.Host
	if cfg.Port > 0 {
		host = fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	}
	c := &Client{
		Config:     cfg,
		Redis:      dep.Redis,
		baseURL:    fmt.Sprintf("%s://%s", scheme, host),
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
	if err := c.registerRoutes(dep.Engine); err != nil {
		return nil, err
	}
	return c, nil
}

// cachedJWKS 返回缓存中的公钥集；force 为 true 或缓存失效时重新拉取。
func (c *Client) cachedJWKS(ctx context.Context, force bool) (common.JWKS, error) {
	if !force && c.Config.JWKSCacheTTL > 0 {
		c.jwksMu.RLock()
		if len(c.jwks.Keys) > 0 && time.Now().Before(c.jwksUntil) {
			j := c.jwks
			c.jwksMu.RUnlock()
			return j, nil
		}
		c.jwksMu.RUnlock()
	}

	jwks, err := c.FetchJWKS(ctx)
	if err != nil {
		return common.JWKS{}, err
	}
	c.jwksMu.Lock()
	c.jwks = jwks
	if c.Config.JWKSCacheTTL > 0 {
		c.jwksUntil = time.Now().Add(c.Config.JWKSCacheTTL)
	}
	c.jwksMu.Unlock()
	return jwks, nil
}

func (c *Client) jwksRefreshCooldownKey() string {
	return c.Config.RedisKeyPrefix + ":jwks_refresh_cooldown"
}

// tryBeginJWKSRefresh 用 Redis SETNX 占用强制刷新冷却窗口。
// 返回 false 表示冷却中，禁止再次拉取公钥。
func (c *Client) tryBeginJWKSRefresh(ctx context.Context) (bool, error) {
	ok, err := c.Redis.SetNX(ctx, c.jwksRefreshCooldownKey(), "1", c.Config.JWKSRefreshCooldown).Result()
	if err != nil {
		return false, err
	}
	return ok, nil
}

// abortJWKSRefresh 拉取失败时解除冷却，允许短暂后重试。
func (c *Client) abortJWKSRefresh(ctx context.Context) {
	_ = c.Redis.Del(ctx, c.jwksRefreshCooldownKey()).Err()
}

// BaseURL 返回授权服务器根地址，例如 http://127.0.0.1:8080
func (c *Client) BaseURL() string { return c.baseURL }

func (c *Client) issuer() string {
	if c.Config.Issuer != "" {
		return c.Config.Issuer
	}
	return c.baseURL
}
