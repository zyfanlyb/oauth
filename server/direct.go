package server

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/zyfanlyb/util/common"
)

// tokenResult 令牌签发结果（供 HTTP 令牌端点组装响应）。
type tokenResult struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int
	RefreshToken string
	Scope        string
	IDToken      string
}

func (s *Server) exchangeAuthorizationCode(ctx context.Context, client *Client, code, redirectURI, codeVerifier string) (*tokenResult, error) {
	if !clientAllowsGrant(client, "authorization_code") {
		return nil, errors.New("unauthorized_client: client not allowed to use authorization_code")
	}
	if code == "" || redirectURI == "" {
		return nil, errors.New("invalid_request: code and redirect_uri are required")
	}

	authCode, err := s.Codes.Take(ctx, code)
	if err != nil || authCode == nil {
		return nil, errors.New("invalid_grant: invalid authorization code")
	}
	if time.Now().After(authCode.ExpiresAt) {
		return nil, errors.New("invalid_grant: authorization code expired")
	}
	if authCode.ClientID != client.ID {
		return nil, errors.New("invalid_grant: code was not issued to this client")
	}
	if authCode.RedirectURI != redirectURI {
		return nil, errors.New("invalid_grant: redirect_uri mismatch")
	}
	if authCode.CodeChallenge != "" {
		if !verifyPKCE(authCode.CodeChallenge, authCode.CodeChallengeMethod, codeVerifier) {
			return nil, errors.New("invalid_grant: invalid code_verifier")
		}
	}

	return s.issueTokens(ctx, client, authCode.Subject, authCode.Scope, authCode.Nonce)
}

func (s *Server) refreshGrant(ctx context.Context, client *Client, refreshToken, scope string) (*tokenResult, error) {
	if !clientAllowsGrant(client, "refresh_token") {
		return nil, errors.New("unauthorized_client: client not allowed to use refresh_token")
	}
	if refreshToken == "" {
		return nil, errors.New("invalid_request: refresh_token is required")
	}

	rt, err := s.Tokens.GetRefresh(ctx, refreshToken)
	if err != nil || rt == nil {
		return nil, errors.New("invalid_grant: invalid refresh_token")
	}
	if time.Now().After(rt.ExpiresAt) {
		return nil, errors.New("invalid_grant: refresh_token expired")
	}
	if rt.ClientID != client.ID {
		return nil, errors.New("invalid_grant: refresh_token was not issued to this client")
	}

	if scope == "" {
		scope = rt.Scope
	} else if !scopeSubset(rt.Scope, scope) {
		return nil, errors.New("invalid_scope: requested scope exceeds original grant")
	}

	_ = s.Tokens.RevokeRefresh(ctx, refreshToken)
	return s.issueTokens(ctx, client, rt.Subject, scope, "")
}

// clientCredentialsGrant 服务端对服务端：客户端凭自身身份换访问令牌，不代表用户。
func (s *Server) clientCredentialsGrant(ctx context.Context, client *Client, scope string) (*tokenResult, error) {
	if client == nil || !client.Confidential {
		return nil, errors.New("unauthorized_client: client_credentials requires a confidential client")
	}
	if !clientAllowsGrant(client, "client_credentials") {
		return nil, errors.New("unauthorized_client: client not allowed to use client_credentials")
	}
	if scope == "" {
		scope = strings.Join(client.Scopes, " ")
	} else if len(client.Scopes) > 0 && !scopesAllowed(client.Scopes, scope) {
		return nil, errors.New("invalid_scope: requested scope is not allowed")
	}
	return s.issueTokenSet(ctx, client, client.ID, scope, "", false)
}

// userInfoByAccessToken 凭 access_token 取用户声明。
func (s *Server) userInfoByAccessToken(ctx context.Context, accessToken string) (map[string]any, error) {
	if accessToken == "" {
		return nil, errors.New("invalid_token: missing access token")
	}
	_, at, err := s.resolveAccessToken(ctx, accessToken)
	if err != nil {
		return nil, errors.New("invalid_token: access token is invalid or expired")
	}
	user, err := s.Users.FindBySubject(ctx, at.Subject)
	if err != nil || user == nil {
		return nil, errors.New("server_error: user not found")
	}

	out := map[string]any{"sub": user.Subject}
	if hasScope(at.Scope, "profile") && user.Name != "" {
		out["name"] = user.Name
	}
	if hasScope(at.Scope, "email") {
		if user.Email != "" {
			out["email"] = user.Email
		}
		out["email_verified"] = user.EmailVerified
	}
	for k, v := range user.Extra {
		out[k] = v
	}
	return out, nil
}

// introspectToken 检视令牌。
func (s *Server) introspectToken(ctx context.Context, clientID, clientSecret, token, hint string) (map[string]any, error) {
	if _, err := s.authenticateClientCreds(ctx, clientID, clientSecret); err != nil {
		return nil, err
	}
	if token == "" {
		return nil, errors.New("invalid_request: token is required")
	}

	inactive := map[string]any{"active": false}
	if hint != "refresh_token" {
		if claims, at, err := s.resolveAccessToken(ctx, token); err == nil {
			return map[string]any{
				"active":     true,
				"client_id":  at.ClientID,
				"sub":        at.Subject,
				"scope":      at.Scope,
				"exp":        at.ExpiresAt.Unix(),
				"token_type": "access_token",
				"iss":        claimString(claims, "iss"),
			}, nil
		}
	}
	if hint != "access_token" {
		if rt, err := s.Tokens.GetRefresh(ctx, token); err == nil && rt != nil {
			if time.Now().Before(rt.ExpiresAt) {
				return map[string]any{
					"active":     true,
					"client_id":  rt.ClientID,
					"sub":        rt.Subject,
					"scope":      rt.Scope,
					"exp":        rt.ExpiresAt.Unix(),
					"token_type": "refresh_token",
				}, nil
			}
		}
	}
	return inactive, nil
}

func (s *Server) authenticateClientCreds(ctx context.Context, clientID, clientSecret string) (*Client, error) {
	if clientID == "" {
		return nil, errors.New("invalid_client: client authentication required")
	}
	client, err := s.Clients.Authenticate(ctx, clientID, clientSecret)
	if err != nil || client == nil {
		return nil, errors.New("invalid_client: invalid client credentials")
	}
	return client, nil
}

func (s *Server) issueTokens(ctx context.Context, client *Client, subject, scope, nonce string) (*tokenResult, error) {
	return s.issueTokenSet(ctx, client, subject, scope, nonce, true)
}

func (s *Server) issueTokenSet(ctx context.Context, client *Client, subject, scope, nonce string, userGrant bool) (*tokenResult, error) {
	cfg := s.Config.withDefaults()
	signer, err := s.signingKey(ctx)
	if err != nil {
		return nil, errors.New("server_error: RS256 keystore is not ready")
	}

	now := time.Now()
	exp := now.Add(cfg.AccessTokenTTL)
	issuer := strings.TrimRight(cfg.Issuer, "/")
	jti, err := randomToken(16)
	if err != nil {
		return nil, errors.New("server_error: failed to create jti")
	}

	accessClaims := common.Claims{
		"iss":       issuer,
		"sub":       subject,
		"aud":       client.ID,
		"client_id": client.ID,
		"scope":     scope,
		"jti":       jti,
		"iat":       now.Unix(),
		"exp":       exp.Unix(),
		"token_use": "access_token",
	}
	if !userGrant {
		accessClaims["token_use"] = "client_credentials"
	}
	access, err := signer.GenerateJWT(accessClaims)
	if err != nil {
		return nil, errors.New("server_error: failed to sign access_token")
	}
	at := &AccessToken{
		Token:     access,
		ClientID:  client.ID,
		Subject:   subject,
		Scope:     scope,
		ExpiresAt: exp,
	}
	if userGrant && clientAllowsGrant(client, "refresh_token") {
		secret, err := randomToken(32)
		if err == nil {
			rt := &RefreshToken{
				Token:     secret,
				ClientID:  client.ID,
				Subject:   subject,
				Scope:     scope,
				ExpiresAt: now.Add(cfg.RefreshTokenTTL),
			}
			if err := s.Tokens.SaveRefresh(ctx, rt); err == nil {
				at.RefreshToken = secret
			}
		}
	}
	if err := s.Tokens.SaveAccess(ctx, at); err != nil {
		if at.RefreshToken != "" {
			_ = s.Tokens.RevokeRefresh(ctx, at.RefreshToken)
		}
		return nil, errors.New("server_error: failed to persist access_token")
	}

	out := &tokenResult{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    int(cfg.AccessTokenTTL.Seconds()),
		Scope:        scope,
		RefreshToken: at.RefreshToken,
	}

	if userGrant && hasScope(scope, "openid") {
		user, err := s.Users.FindBySubject(ctx, subject)
		if err == nil && user != nil {
			idClaims := common.Claims{
				"iss": issuer,
				"sub": user.Subject,
				"aud": client.ID,
				"exp": exp.Unix(),
				"iat": now.Unix(),
			}
			if nonce != "" {
				idClaims["nonce"] = nonce
			}
			if idToken, err := signer.GenerateJWT(idClaims); err == nil {
				out.IDToken = idToken
			}
		}
	}
	return out, nil
}
