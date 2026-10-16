package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zyfanlyb/util/common"
)

// ---------- 发现文档 ----------

// Metadata 授权服务器元数据（RFC 8414）。
func (s *Server) Metadata(c *gin.Context) {
	issuer := strings.TrimRight(s.Config.Issuer, "/")
	c.JSON(http.StatusOK, gin.H{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oauth/authorize",
		"token_endpoint":                        issuer + "/oauth/token",
		"revocation_endpoint":                   issuer + "/oauth/revoke",
		"introspection_endpoint":                issuer + "/oauth/introspect",
		"jwks_uri":                              issuer + "/oauth/jwks",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256", "plain"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
	})
}

// OpenIDConfiguration OIDC 发现文档。
func (s *Server) OpenIDConfiguration(c *gin.Context) {
	issuer := strings.TrimRight(s.Config.Issuer, "/")
	c.JSON(http.StatusOK, gin.H{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oauth/authorize",
		"token_endpoint":                        issuer + "/oauth/token",
		"userinfo_endpoint":                     issuer + "/oauth/userinfo",
		"jwks_uri":                              issuer + "/oauth/jwks",
		"revocation_endpoint":                   issuer + "/oauth/revoke",
		"introspection_endpoint":                issuer + "/oauth/introspect",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"claims_supported":                      []string{"sub", "name", "email", "email_verified"},
		"code_challenge_methods_supported":      []string{"S256", "plain"},
	})
}

// ---------- 授权端点 ----------

// Authorize 授权端点（RFC 6749 §4.1.1）：
// 校验参数 → 未登录则跳转登录 → 已登录则展示同意页 →（由 ConsentSubmit 签发 code）。
func (s *Server) Authorize(c *gin.Context) {
	cfg := s.Config.withDefaults()
	req := authRequestFromQuery(c)

	if req.ClientID == "" {
		oauthErrorJSON(c, http.StatusBadRequest, "invalid_request", "client_id is required")
		return
	}
	client, err := s.Clients.Get(c.Request.Context(), req.ClientID)
	if err != nil || client == nil {
		oauthErrorJSON(c, http.StatusBadRequest, "invalid_client", "unknown client_id")
		return
	}
	if req.RedirectURI == "" || !validRedirectURI(client, req.RedirectURI) {
		oauthErrorJSON(c, http.StatusBadRequest, "invalid_request", "invalid redirect_uri")
		return
	}
	if msg := validateAuthRequest(cfg, client, req); msg != "" {
		code := "invalid_request"
		if msg == "only response_type=code is supported" {
			code = "unsupported_response_type"
		} else if strings.Contains(msg, "scope") {
			code = "invalid_scope"
		}
		redirectOAuthError(c, req.RedirectURI, code, msg, req.State)
		return
	}

	prompts := strings.Fields(req.Prompt)
	forceLogin := hasPrompt(prompts, "login")
	promptNone := hasPrompt(prompts, "none")

	var user *UserClaims
	if forceLogin {
		s.clearSessionCookie(c)
	} else {
		var err error
		user, err = s.CurrentSessionUser(c)
		if err != nil {
			oauthErrorJSON(c, http.StatusInternalServerError, "server_error", "failed to resolve current user")
			return
		}
	}
	if user == nil || user.Subject == "" {
		if promptNone {
			redirectOAuthError(c, req.RedirectURI, "login_required", "end-user authentication is required", req.State)
			return
		}
		// return_to 使用相对路径，登录后回到本授权端点
		c.Redirect(http.StatusFound, s.loginURL(c.Request.URL.RequestURI()))
		return
	}

	// 已登录：进入用户同意步骤（标准授权码流程的交互部分）
	if promptNone {
		redirectOAuthError(c, req.RedirectURI, "interaction_required", "user consent is required", req.State)
		return
	}
	s.renderConsent(c, user, req)
}

// ---------- 令牌端点 ----------

// Token 令牌端点：authorization_code / refresh_token / client_credentials。
func (s *Server) Token(c *gin.Context) {
	cfg := s.Config.withDefaults()
	_ = c.Request.ParseForm()

	client, err := s.authenticateClient(c)
	if err != nil {
		c.Header("WWW-Authenticate", `Basic realm="oauth"`)
		oauthErrorJSON(c, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}

	grantType := c.PostForm("grant_type")
	switch grantType {
	case "authorization_code":
		s.tokenAuthorizationCode(c, cfg, client)
	case "refresh_token":
		s.tokenRefresh(c, cfg, client)
	case "client_credentials":
		s.tokenClientCredentials(c, client)
	default:
		oauthErrorJSON(c, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type")
	}
}

func (s *Server) tokenAuthorizationCode(c *gin.Context, cfg Config, client *Client) {
	_ = cfg
	res, err := s.exchangeAuthorizationCode(
		c.Request.Context(),
		client,
		c.PostForm("code"),
		c.PostForm("redirect_uri"),
		c.PostForm("code_verifier"),
	)
	if err != nil {
		writeOAuthServiceError(c, err)
		return
	}
	writeTokenResult(c, res)
}

func (s *Server) tokenClientCredentials(c *gin.Context, client *Client) {
	res, err := s.clientCredentialsGrant(c.Request.Context(), client, c.PostForm("scope"))
	if err != nil {
		writeOAuthServiceError(c, err)
		return
	}
	writeTokenResult(c, res)
}

func (s *Server) tokenRefresh(c *gin.Context, cfg Config, client *Client) {
	_ = cfg
	res, err := s.refreshGrant(
		c.Request.Context(),
		client,
		c.PostForm("refresh_token"),
		c.PostForm("scope"),
	)
	if err != nil {
		writeOAuthServiceError(c, err)
		return
	}
	writeTokenResult(c, res)
}

func writeTokenResult(c *gin.Context, res *tokenResult) {
	resp := gin.H{
		"access_token": res.AccessToken,
		"token_type":   res.TokenType,
		"expires_in":   res.ExpiresIn,
	}
	if res.Scope != "" {
		resp["scope"] = res.Scope
	}
	if res.RefreshToken != "" {
		resp["refresh_token"] = res.RefreshToken
	}
	if res.IDToken != "" {
		resp["id_token"] = res.IDToken
	}
	c.JSON(http.StatusOK, resp)
}

// writeOAuthServiceError 将业务错误 "code: desc" 映射为 OAuth JSON。
func writeOAuthServiceError(c *gin.Context, err error) {
	msg := err.Error()
	code, desc := "invalid_request", msg
	if i := strings.Index(msg, ": "); i > 0 {
		code, desc = msg[:i], msg[i+2:]
	}
	status := http.StatusBadRequest
	switch code {
	case "invalid_client":
		status = http.StatusUnauthorized
		c.Header("WWW-Authenticate", `Basic realm="oauth"`)
	case "server_error":
		status = http.StatusInternalServerError
	}
	oauthErrorJSON(c, status, code, desc)
}

// ---------- 撤销 / 检视 ----------

// Revoke 令牌撤销（RFC 7009）。无论令牌是否存在都返回 200。
func (s *Server) Revoke(c *gin.Context) {
	_ = c.Request.ParseForm()
	if _, err := s.authenticateClient(c); err != nil {
		c.Header("WWW-Authenticate", `Basic realm="oauth"`)
		oauthErrorJSON(c, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}
	token := c.PostForm("token")
	if token == "" {
		oauthErrorJSON(c, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}
	hint := c.PostForm("token_type_hint")
	ctx := c.Request.Context()
	switch hint {
	case "refresh_token":
		_ = s.Tokens.RevokeRefresh(ctx, token)
		_ = s.Tokens.RevokeAccess(ctx, token)
	default:
		_ = s.Tokens.RevokeAccess(ctx, token)
		_ = s.Tokens.RevokeRefresh(ctx, token)
	}
	c.Status(http.StatusOK)
}

// Introspect 令牌检视（RFC 7662）。
func (s *Server) Introspect(c *gin.Context) {
	_ = c.Request.ParseForm()
	id, secret, _ := c.Request.BasicAuth()
	if id == "" {
		id = c.PostForm("client_id")
		secret = c.PostForm("client_secret")
	}
	out, err := s.introspectToken(c.Request.Context(), id, secret, c.PostForm("token"), c.PostForm("token_type_hint"))
	if err != nil {
		writeOAuthServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

// ---------- UserInfo / JWKS ----------

// UserInfo 用户信息端点（OIDC）：校验 RS256 access_token 后返回用户声明。
func (s *Server) UserInfo(c *gin.Context) {
	token := bearerToken(c)
	out, err := s.userInfoByAccessToken(c.Request.Context(), token)
	if err != nil {
		msg := err.Error()
		if strings.HasPrefix(msg, "invalid_token") {
			c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
			writeOAuthServiceError(c, err)
			return
		}
		writeOAuthServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

// JWKS 返回 RS256 公钥集（业务系统据此验签）。
func (s *Server) JWKS(c *gin.Context) {
	doc, err := s.buildJWKS(c.Request.Context())
	if err != nil {
		oauthErrorJSON(c, http.StatusInternalServerError, "server_error", "failed to load JWKS")
		return
	}
	c.Header("Cache-Control", "public, max-age=3600")
	c.JSON(http.StatusOK, doc)
}

// ---------- 辅助函数 ----------

type clientAuthError struct{ msg string }

func (e *clientAuthError) Error() string { return e.msg }

// resolveAccessToken 用 RS256 公钥验签，并确认尚未被撤销（仍存在于 TokenStore）。
func (s *Server) resolveAccessToken(ctx context.Context, raw string) (common.Claims, *AccessToken, error) {
	pub, err := s.publicKeyForToken(ctx, raw)
	if err != nil {
		return nil, nil, err
	}
	claims, err := common.Verify(raw, pub, common.VerifyOptions{
		Issuer: strings.TrimRight(s.Config.Issuer, "/"),
	})
	if err != nil {
		return nil, nil, err
	}
	at, err := s.Tokens.GetAccess(ctx, raw)
	if err != nil || at == nil {
		return nil, nil, errors.New("token revoked or unknown")
	}
	if time.Now().After(at.ExpiresAt) {
		return nil, nil, errors.New("token expired")
	}
	return claims, at, nil
}

func claimString(claims common.Claims, key string) string {
	s, _ := claims.GetString(key)
	return s
}

func (s *Server) authenticateClient(c *gin.Context) (*Client, error) {
	clientID, clientSecret, ok := c.Request.BasicAuth()
	if !ok {
		clientID = c.PostForm("client_id")
		clientSecret = c.PostForm("client_secret")
	}
	if clientID == "" {
		return nil, &clientAuthError{"client authentication required"}
	}
	client, err := s.Clients.Authenticate(c.Request.Context(), clientID, clientSecret)
	if err != nil || client == nil {
		return nil, &clientAuthError{"invalid client credentials"}
	}
	return client, nil
}

func oauthErrorJSON(c *gin.Context, status int, code, desc string) {
	c.JSON(status, gin.H{
		"error":             code,
		"error_description": desc,
	})
}

func redirectOAuthError(c *gin.Context, redirectURI, code, desc, state string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		oauthErrorJSON(c, http.StatusBadRequest, code, desc)
		return
	}
	vals := u.Query()
	vals.Set("error", code)
	vals.Set("error_description", desc)
	if state != "" {
		vals.Set("state", state)
	}
	u.RawQuery = vals.Encode()
	c.Redirect(http.StatusFound, u.String())
}

func validRedirectURI(client *Client, redirectURI string) bool {
	for _, u := range client.RedirectURIs {
		if u == redirectURI {
			return true
		}
	}
	return false
}

func clientAllowsGrant(client *Client, grant string) bool {
	if len(client.GrantTypes) == 0 {
		return grant == "authorization_code" || grant == "refresh_token"
	}
	for _, g := range client.GrantTypes {
		if g == grant {
			return true
		}
	}
	return false
}

func scopesAllowed(allowed []string, requested string) bool {
	set := make(map[string]struct{}, len(allowed))
	for _, s := range allowed {
		set[s] = struct{}{}
	}
	for _, s := range strings.Fields(requested) {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}

func scopeSubset(original, requested string) bool {
	set := make(map[string]struct{})
	for _, s := range strings.Fields(original) {
		set[s] = struct{}{}
	}
	for _, s := range strings.Fields(requested) {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}

func hasScope(scope, want string) bool {
	for _, s := range strings.Fields(scope) {
		if s == want {
			return true
		}
	}
	return false
}

func bearerToken(c *gin.Context) string {
	h := c.GetHeader("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	if t := c.Query("access_token"); t != "" {
		return t
	}
	_ = c.Request.ParseForm()
	return c.PostForm("access_token")
}

func verifyPKCE(challenge, method, verifier string) bool {
	if verifier == "" {
		return false
	}
	switch method {
	case "", "plain":
		return subtle.ConstantTimeCompare([]byte(challenge), []byte(verifier)) == 1
	case "S256":
		sum := sha256.Sum256([]byte(verifier))
		encoded := base64.RawURLEncoding.EncodeToString(sum[:])
		return subtle.ConstantTimeCompare([]byte(challenge), []byte(encoded)) == 1
	default:
		return false
	}
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func absoluteRequestURL(c *gin.Context) string {
	scheme := "http"
	if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + c.Request.Host + c.Request.URL.RequestURI()
}
