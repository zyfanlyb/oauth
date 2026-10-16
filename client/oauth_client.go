package client

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/zyfanlyb/util/common"
)

// Token 令牌端点响应。
type Token struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// pkce 挑战对：AuthorizationURL 生成并写入 Redis，回调换票时取出。
type pkce struct {
	Verifier        string
	Challenge       string
	ChallengeMethod string // S256
}

// ---------- 授权码流程（包内） ----------

func (c *Client) authCodeURL(state string, p *pkce, nonce string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", c.Config.ClientID)
	if c.Config.RedirectURI != "" {
		q.Set("redirect_uri", c.Config.RedirectURI)
	}
	if c.Config.Scopes != "" {
		q.Set("scope", c.Config.Scopes)
	}
	if state != "" {
		q.Set("state", state)
	}
	if p != nil {
		q.Set("code_challenge", p.Challenge)
		q.Set("code_challenge_method", p.ChallengeMethod)
	}
	if nonce != "" {
		q.Set("nonce", nonce)
	}
	return c.baseURL + "/oauth/authorize?" + q.Encode()
}

// exchange 向令牌端点换票。code 为空时换客户端凭证，否则用授权码换用户令牌。
// scope 仅在 code 为空时有效，空则用 Config.Scopes。
func (c *Client) exchange(ctx context.Context, code, scope string, p *pkce) (*Token, error) {
	form := url.Values{}
	form.Set("client_id", c.Config.ClientID)
	if c.Config.ClientSecret != "" {
		form.Set("client_secret", c.Config.ClientSecret)
	}
	if code == "" {
		form.Set("grant_type", "client_credentials")
		if scope == "" {
			scope = c.Config.Scopes
		}
		if scope != "" {
			form.Set("scope", scope)
		}
		return c.tokenRequest(ctx, form)
	}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", c.Config.RedirectURI)
	if p != nil && p.Verifier != "" {
		form.Set("code_verifier", p.Verifier)
	}
	return c.tokenRequest(ctx, form)
}

// refresh 用 refresh_token 刷新令牌（包内使用，不向依赖方暴露）。
func (c *Client) refresh(ctx context.Context, refreshToken string, scope string) (*Token, error) {
	if refreshToken == "" {
		return nil, errors.New("refresh_token is required")
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", c.Config.ClientID)
	if c.Config.ClientSecret != "" {
		form.Set("client_secret", c.Config.ClientSecret)
	}
	if scope != "" {
		form.Set("scope", scope)
	}
	return c.tokenRequest(ctx, form)
}

// ---------- 撤销 / 检视 ----------

// Revoke 撤销 access_token 或 refresh_token。
func (c *Client) Revoke(ctx context.Context, token, tokenTypeHint string) error {
	form := url.Values{}
	form.Set("token", token)
	if tokenTypeHint != "" {
		form.Set("token_type_hint", tokenTypeHint)
	}
	form.Set("client_id", c.Config.ClientID)
	if c.Config.ClientSecret != "" {
		form.Set("client_secret", c.Config.ClientSecret)
	}
	resp, err := c.postForm(ctx, c.baseURL+"/oauth/revoke", form)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return oauthHTTPError("revoke", resp.StatusCode, body)
	}
	return nil
}

// Introspect 向授权服务器检视令牌是否有效。
func (c *Client) Introspect(ctx context.Context, token, tokenTypeHint string) (map[string]any, error) {
	form := url.Values{}
	form.Set("token", token)
	if tokenTypeHint != "" {
		form.Set("token_type_hint", tokenTypeHint)
	}
	form.Set("client_id", c.Config.ClientID)
	if c.Config.ClientSecret != "" {
		form.Set("client_secret", c.Config.ClientSecret)
	}
	resp, err := c.postForm(ctx, c.baseURL+"/oauth/introspect", form)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, oauthHTTPError("introspect", resp.StatusCode, body)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ---------- JWKS / 本地验签 ----------

// FetchJWKS 拉取授权服务器公钥集。
func (c *Client) FetchJWKS(ctx context.Context) (common.JWKS, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/oauth/jwks", nil)
	if err != nil {
		return common.JWKS{}, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return common.JWKS{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return common.JWKS{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return common.JWKS{}, oauthHTTPError("jwks", resp.StatusCode, body)
	}
	var jwks common.JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return common.JWKS{}, err
	}
	return jwks, nil
}

// verifyJWT 用 JWKS 中的公钥本地校验 RS256 access_token。
// issuer 空则使用 Config.Issuer，再空则用 BaseURL；并校验 aud == ClientID。
func (c *Client) verifyJWT(token string, jwks common.JWKS, issuer string) (common.Claims, error) {
	if issuer == "" {
		issuer = c.issuer()
	}
	pub, err := publicKeyFromToken(token, jwks)
	if err != nil {
		return nil, err
	}
	return common.Verify(token, pub, common.VerifyOptions{
		Issuer:   issuer,
		Audience: c.Config.ClientID,
	})
}

// ---------- PKCE / state（包内） ----------

func newPKCE() (*pkce, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	verifier := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	return &pkce{
		Verifier:        verifier,
		Challenge:       base64.RawURLEncoding.EncodeToString(sum[:]),
		ChallengeMethod: "S256",
	}, nil
}

func randomState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ---------- 内部 ----------

func (c *Client) tokenRequest(ctx context.Context, form url.Values) (*Token, error) {
	resp, err := c.postForm(ctx, c.baseURL+"/oauth/token", form)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, oauthHTTPError("token", resp.StatusCode, body)
	}
	var tok Token
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, err
	}
	return &tok, nil
}

func (c *Client) postForm(ctx context.Context, endpoint string, form url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.httpClient.Do(req)
}

func oauthHTTPError(op string, status int, body []byte) error {
	return fmt.Errorf("oauth %s: status %d: %s", op, status, strings.TrimSpace(string(body)))
}

func publicKeyFromToken(token string, jwks common.JWKS) (*rsa.PublicKey, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, common.ErrInvalidFormat
	}
	hdrJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, common.ErrInvalidFormat
	}
	var hdr struct {
		KID string `json:"kid"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		return nil, common.ErrInvalidFormat
	}
	if hdr.Alg != "" && hdr.Alg != common.AlgRS256 {
		return nil, common.ErrAlgNotAllowed
	}
	if hdr.KID != "" {
		return common.LookupPublicKey(jwks, hdr.KID)
	}
	if len(jwks.Keys) == 0 {
		return nil, common.ErrUnknownKID
	}
	return common.ParseRSAPublicKey(jwks.Keys[0])
}
