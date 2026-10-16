package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/zyfanlyb/util/common"
)

// 本文件：业务系统可直接调用的开放方法。
//
//	AuthorizationURL   — 生成跳转授权中心的 URL（state 必做；PKCE/nonce 看 Config 开关）
//	ClientCredentials  — 取客户端凭证；Redis 有未过期令牌则直接返回，否则换票并写入 Redis
//	RevokeToken        — 撤销 access_token 或 refresh_token
//	VerifyAccessToken  — 校验 Authorization: Bearer ...（RealtimeVerify 为 false 时本地验签，为 true 时只问 introspect）
//	CurrentPrincipal   — 从 gin.Context 取出中间件写入的当前用户（后续接口用）
//
// 浏览器登录：registerRoutes 在 RedirectURI 同级挂 GET .../login，内部生成授权地址并 302；回调按 RedirectURI 挂上并内部完成授权码换票。
// 客户端凭证：ClientCredentials(ctx, scope)。
// 鉴权通过后：p, ok := client.CurrentPrincipal(c)；ok 为 true 时使用 p.Subject 等字段。
// state 始终由本包生成；UsePKCE / UseNonce 仅在依赖方 New 时配置开启才会做。
// access_token 续期由本包内部处理，不向依赖方暴露刷新接口。
// RealtimeVerify 为 false 时只验本地 JWT；为 true 时只请求 /oauth/introspect，由授权中心验签并确认未撤销。
// kid 未命中时会刷新 JWKS 并重验；刷新带 Redis 冷却，防止伪造 kid 刷公钥。
// EnableAuthMiddleware 开启时，New 会自动向 Engine 挂载中间件。
// 接入步骤见 deps.go 顶部说明；创建客户端用 New。

// ErrJWKSRefreshCooling kid 未命中，且 JWKS 强制刷新仍在冷却期内。
var ErrJWKSRefreshCooling = errors.New("jwks refresh cooling down")

// AccessPrincipal 本地验签通过后的调用方身份（来自 access_token JWT）。
type AccessPrincipal struct {
	Subject   string        // sub
	ClientID  string        // aud / client_id
	Scope     string        // scope
	Name      string        // name（JWT 中有则带出）
	Email     string        // email（JWT 中有则带出）
	ExpiresAt time.Time     // exp
	Claims    common.Claims // 完整声明
}

// AuthorizationURL 生成跳转授权中心的 URL。
// state 始终生成并写入 Redis；PKCE / nonce 仅当 Config.UsePKCE / UseNonce 为 true 时生成。
func (c *Client) AuthorizationURL(ctx context.Context) (string, error) {
	state, err := randomState()
	if err != nil {
		return "", err
	}

	pending := pendingAuth{}
	var p *pkce
	if c.Config.UsePKCE {
		p, err = newPKCE()
		if err != nil {
			return "", err
		}
		pending.Verifier = p.Verifier
		pending.Challenge = p.Challenge
		pending.ChallengeMethod = p.ChallengeMethod
	}
	if c.Config.UseNonce {
		nonce, err := randomState()
		if err != nil {
			return "", err
		}
		pending.Nonce = nonce
	}

	raw, err := json.Marshal(pending)
	if err != nil {
		return "", err
	}
	if err := c.Redis.Set(ctx, c.authRequestKey(state), string(raw), c.Config.AuthRequestTTL).Err(); err != nil {
		return "", err
	}
	return c.authCodeURL(state, p, pending.Nonce), nil
}

// ClientCredentials 获取客户端凭证。
// Redis 中已有未过期令牌则直接返回；没有则向令牌端点换票并按 expires_in 写入 Redis。
// scope 为空时使用 Config.Scopes。
func (c *Client) ClientCredentials(ctx context.Context, scope string) (*Token, error) {
	if c.Config.ClientSecret == "" {
		return nil, errors.New("client_secret is required")
	}
	if scope == "" {
		scope = c.Config.Scopes
	}
	key := c.clientCredentialsKey(scope)
	raw, err := c.Redis.Get(ctx, key).Result()
	if err == nil {
		var cached Token
		if json.Unmarshal([]byte(raw), &cached) == nil && cached.AccessToken != "" {
			return &cached, nil
		}
	} else if err != redis.Nil {
		return nil, err
	}

	tok, err := c.exchange(ctx, "", scope, nil)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(tok)
	if err != nil {
		return nil, err
	}
	ttl := time.Duration(tok.ExpiresIn) * time.Second
	if ttl > 30*time.Second {
		ttl -= 30 * time.Second
	}
	if ttl <= 0 {
		ttl = time.Minute
	}
	if err := c.Redis.Set(ctx, key, string(b), ttl).Err(); err != nil {
		return nil, err
	}
	return tok, nil
}

// RevokeToken 撤销 access_token 或 refresh_token。
// hint 可为 "access_token" / "refresh_token"，不确定可传空。
func (c *Client) RevokeToken(ctx context.Context, token, hint string) error {
	if token == "" {
		return errors.New("token is required")
	}
	return c.Revoke(ctx, token, hint)
}

// VerifyAccessToken 校验请求头中的 Bearer token。
// authorization 须为完整头值，例如 "Bearer eyJhbGciOiJSUzI1NiJ9..."。
// RealtimeVerify 为 false 时本地验签，并校验 iss、aud。
// 为 true 时只请求 /oauth/introspect，授权中心验签并确认令牌未撤销；客户端再核对 iss 与 client_id。
func (c *Client) VerifyAccessToken(ctx context.Context, authorization string) (*AccessPrincipal, error) {
	const prefix = "Bearer "
	authorization = strings.TrimSpace(authorization)
	if len(authorization) < len(prefix) || !strings.EqualFold(authorization[:len(prefix)], prefix) {
		return nil, errors.New("missing bearer token")
	}
	raw := strings.TrimSpace(authorization[len(prefix):])
	if raw == "" {
		return nil, errors.New("missing bearer token")
	}

	if c.Config.RealtimeVerify {
		return c.principalFromIntrospect(ctx, raw)
	}
	claims, err := c.verifyWithJWKS(ctx, raw)
	if err != nil {
		return nil, err
	}
	return principalFromClaims(claims), nil
}

// CurrentPrincipal 从 gin.Context 取出鉴权中间件写入的当前用户信息。
// 仅在经过 AuthMiddleware 且鉴权成功的请求中 ok=true；白名单跳过鉴权时一般为 false。
//
//	p, ok := client.CurrentPrincipal(c)
//	if !ok { ... }
//	sub := p.Subject
func CurrentPrincipal(c *gin.Context) (*AccessPrincipal, bool) {
	if c == nil {
		return nil, false
	}
	v, ok := c.Get(contextKeyPrincipal)
	if !ok {
		return nil, false
	}
	p, ok := v.(*AccessPrincipal)
	return p, ok && p != nil
}

// ---------- 内部 ----------

// pendingAuth 授权中间态：AuthorizationURL 写入，回调换票时取出后删除。
type pendingAuth struct {
	Verifier        string `json:"verifier,omitempty"`
	Challenge       string `json:"challenge,omitempty"`
	ChallengeMethod string `json:"challenge_method,omitempty"`
	Nonce           string `json:"nonce,omitempty"`
}

// exchangeAuthorizationCode 用回调中的授权码换取令牌（不向依赖方暴露）。
func (c *Client) exchangeAuthorizationCode(ctx context.Context, code, state string) (*Token, error) {
	if code == "" {
		return nil, errors.New("authorization code is required")
	}
	if state == "" {
		return nil, errors.New("state is required")
	}
	key := c.authRequestKey(state)
	raw, err := c.Redis.Get(ctx, key).Result()
	if err == redis.Nil {
		return nil, errors.New("invalid or expired state")
	}
	if err != nil {
		return nil, err
	}
	_ = c.Redis.Del(ctx, key).Err()
	var pending pendingAuth
	if err := json.Unmarshal([]byte(raw), &pending); err != nil {
		return nil, err
	}

	var p *pkce
	if c.Config.UsePKCE {
		if pending.Verifier == "" {
			return nil, errors.New("pkce verifier missing for this authorization request")
		}
		p = &pkce{
			Verifier:        pending.Verifier,
			Challenge:       pending.Challenge,
			ChallengeMethod: pending.ChallengeMethod,
		}
	}

	tok, err := c.exchange(ctx, code, "", p)
	if err != nil {
		return nil, err
	}
	if c.Config.UseNonce {
		if err := c.verifyIDTokenNonce(ctx, tok.IDToken, pending.Nonce); err != nil {
			return nil, err
		}
	}
	return tok, nil
}

func (c *Client) verifyIDTokenNonce(ctx context.Context, idToken, wantNonce string) error {
	if wantNonce == "" {
		return errors.New("nonce missing for this authorization request")
	}
	if idToken == "" {
		return errors.New("id_token missing; enable openid scope when UseNonce is true")
	}
	claims, err := c.verifyWithJWKS(ctx, idToken)
	if err != nil {
		return err
	}
	got, ok := claims.GetString("nonce")
	if !ok || got != wantNonce {
		return errors.New("id_token nonce mismatch")
	}
	return nil
}

func (c *Client) principalFromIntrospect(ctx context.Context, raw string) (*AccessPrincipal, error) {
	out, err := c.Introspect(ctx, raw, "access_token")
	if err != nil {
		return nil, err
	}
	active, _ := out["active"].(bool)
	tokenType, _ := out["token_type"].(string)
	clientID, _ := out["client_id"].(string)
	iss, _ := out["iss"].(string)
	if !active || tokenType != "access_token" || clientID != c.Config.ClientID || strings.TrimRight(iss, "/") != strings.TrimRight(c.issuer(), "/") {
		return nil, errors.New("token is inactive")
	}
	sub, _ := out["sub"].(string)
	scope, _ := out["scope"].(string)
	var exp int64
	switch v := out["exp"].(type) {
	case float64:
		exp = int64(v)
	case int64:
		exp = v
	}
	return principalFromClaims(common.Claims{
		"iss":       iss,
		"sub":       sub,
		"aud":       clientID,
		"client_id": clientID,
		"scope":     scope,
		"exp":       exp,
	}), nil
}

func (c *Client) authRequestKey(state string) string {
	return c.Config.RedisKeyPrefix + ":authreq:" + state
}

func (c *Client) clientCredentialsKey(scope string) string {
	return c.Config.RedisKeyPrefix + ":client_credentials:" + url.QueryEscape(c.Config.ClientID) + ":" + url.QueryEscape(scope)
}

func principalFromClaims(claims common.Claims) *AccessPrincipal {
	p := &AccessPrincipal{Claims: claims}
	if v, ok := claims.GetString("sub"); ok {
		p.Subject = v
	}
	if v, ok := claims.GetString("client_id"); ok {
		p.ClientID = v
	} else if v, ok := claims.GetString("aud"); ok {
		p.ClientID = v
	}
	if v, ok := claims.GetString("scope"); ok {
		p.Scope = v
	}
	if v, ok := claims.GetString("name"); ok {
		p.Name = v
	}
	if v, ok := claims.GetString("email"); ok {
		p.Email = v
	}
	if exp, ok := claims.GetInt64("exp"); ok {
		p.ExpiresAt = time.Unix(exp, 0)
	}
	return p
}

// verifyWithJWKS 用缓存公钥验签；kid 未命中则在冷却允许下刷新 JWKS 再验一次。
func (c *Client) verifyWithJWKS(ctx context.Context, accessToken string) (common.Claims, error) {
	jwks, err := c.cachedJWKS(ctx, false)
	if err != nil {
		return nil, err
	}
	claims, err := c.verifyJWT(accessToken, jwks, "")
	if err == nil {
		return claims, nil
	}
	if !errors.Is(err, common.ErrUnknownKID) {
		return nil, err
	}

	// kid 未命中：Redis SETNX 占冷却窗口后再拉公钥
	began, err := c.tryBeginJWKSRefresh(ctx)
	if err != nil {
		return nil, err
	}
	if !began {
		return nil, ErrJWKSRefreshCooling
	}

	jwks, err = c.cachedJWKS(ctx, true)
	if err != nil {
		c.abortJWKSRefresh(ctx)
		return nil, err
	}
	return c.verifyJWT(accessToken, jwks, "")
}
