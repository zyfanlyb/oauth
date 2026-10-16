package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zyfanlyb/util/common"
)

// 本文件：业务系统可直接调用的开放方法。
//
//	CurrentSessionUser  — 取当前登录用户（Cookie 会话）
//	Logout              — 退出登录
//	VerifyAccessToken   — 校验 Authorization: Bearer ...
//	GetRefreshToken     — 查询 refresh_token
//	RevokeToken         — 撤销令牌
//	SigningKey          — 取当前签发用私钥（KeyStore）
//	PublicJWKS          — 取公钥集
//	RotateKeysNow       — 立即轮换密钥
//
// 接入步骤见 deps.go 顶部说明；创建服务用 New（自动挂路由）。

// CurrentSessionUser 从 Cookie 会话读取当前登录用户。
func (s *Server) CurrentSessionUser(c *gin.Context) (*UserClaims, error) {
	if s.sessions == nil {
		return nil, nil
	}
	sid, err := c.Cookie(s.Config.SessionCookie)
	if err != nil || sid == "" {
		return nil, nil
	}
	return s.sessions.Get(c.Request.Context(), sid)
}

// Logout 清除登录会话；可作为 HTTP 处理函数，也可由业务系统直接调用。
func (s *Server) Logout(c *gin.Context) {
	s.clearSessionCookie(c)
	if returnTo := c.Query("return_to"); returnTo != "" && safeReturnTo(returnTo) {
		c.Redirect(http.StatusFound, returnTo)
		return
	}
	c.Status(http.StatusOK)
}

// VerifyAccessToken 校验请求头中的 Bearer token（RS256 验签 + Redis 未撤销）。
// authorization 须为完整头值，例如 "Bearer eyJhbGciOiJSUzI1NiJ9..."。
func (s *Server) VerifyAccessToken(ctx context.Context, authorization string) (*AccessToken, common.Claims, error) {
	const prefix = "Bearer "
	if len(authorization) < len(prefix) || !strings.EqualFold(authorization[:len(prefix)], prefix) {
		return nil, nil, errors.New("missing bearer token")
	}
	claims, at, err := s.resolveAccessToken(ctx, strings.TrimSpace(authorization[len(prefix):]))
	if err != nil {
		return nil, nil, err
	}
	return at, claims, nil
}

// GetRefreshToken 查询 refresh_token 元数据。
func (s *Server) GetRefreshToken(ctx context.Context, refreshToken string) (*RefreshToken, error) {
	if s.Tokens == nil {
		return nil, errors.New("token store not ready")
	}
	rt, err := s.Tokens.GetRefresh(ctx, refreshToken)
	if err != nil {
		return nil, err
	}
	if rt == nil || time.Now().After(rt.ExpiresAt) {
		return nil, errors.New("refresh token invalid or expired")
	}
	return rt, nil
}

// RevokeToken 撤销 access 或 refresh 令牌；hint 可为 "access_token" / "refresh_token"。
func (s *Server) RevokeToken(ctx context.Context, token, hint string) error {
	if s.Tokens == nil {
		return errors.New("token store not ready")
	}
	switch hint {
	case "refresh_token":
		_ = s.Tokens.RevokeRefresh(ctx, token)
		return s.Tokens.RevokeAccess(ctx, token)
	default:
		_ = s.Tokens.RevokeAccess(ctx, token)
		return s.Tokens.RevokeRefresh(ctx, token)
	}
}

// SigningKey 返回当前用于签发的 RS256 密钥（含私钥）。密钥由本包托管在 Redis。
func (s *Server) SigningKey(ctx context.Context) (*common.KeyStore, error) {
	return s.signingKey(ctx)
}

// PublicJWKS 返回当前公钥集（含轮换期内旧钥），与 /oauth/jwks 一致。
func (s *Server) PublicJWKS(ctx context.Context) (common.JWKS, error) {
	return s.buildJWKS(ctx)
}

// RotateKeysNow 立即生成并启用一把新密钥；旧钥按 KeyRetainFor 保留在 JWKS 中。
func (s *Server) RotateKeysNow(ctx context.Context) error {
	return s.withKeyLock(ctx, func() error {
		b, err := s.loadKeyBundle(ctx)
		if err != nil {
			return err
		}
		if b == nil {
			b = &keyBundle{}
		}
		ks, err := common.NewKeyStore()
		if err != nil {
			return err
		}
		sk, err := keyStoreToStored(ks, time.Now())
		if err != nil {
			return err
		}
		now := time.Now()
		b.CurrentKID = sk.KID
		b.Keys = append(b.Keys, sk)
		b.Keys = pruneKeys(b.Keys, b.CurrentKID, now, s.Config.KeyRetainFor)
		if err := s.saveKeyBundle(ctx, b); err != nil {
			return err
		}
		s.cacheBundle(b)
		return nil
	})
}
