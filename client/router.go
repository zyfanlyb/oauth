package client

import (
	"errors"
	"net/http"
	"net/url"
	"path"

	"github.com/gin-gonic/gin"
)

// registerRoutes 挂载依赖方登录入口与授权回调（由 New 调用）。
// RedirectURI 为 http://localhost:11000/auth/callback 时，登录路径为 /auth/login。
func (c *Client) registerRoutes(engine *gin.Engine) error {
	if c.Config.EnableAuthMiddleware {
		engine.Use(c.AuthMiddleware())
	}
	if c.Config.RedirectURI == "" {
		return nil
	}
	u, err := url.Parse(c.Config.RedirectURI)
	if err != nil || u.Path == "" || u.Path == "/" {
		return errors.New("RedirectURI 必须是带路径的回调地址")
	}
	loginPath := path.Join(path.Dir(u.Path), "login")
	if loginPath == u.Path {
		return errors.New("登录路径与回调路径冲突")
	}

	// 浏览器登录入口：生成授权地址并 302 到认证中心
	engine.GET(loginPath, c.handleAuthorizationLogin)

	// 授权回调：用 code、state 换票，PKCE / nonce 在包内完成
	engine.GET(u.Path, c.handleAuthorizationCallback)
	return nil
}

func (c *Client) handleAuthorizationLogin(ctx *gin.Context) {
	authURL, err := c.AuthorizationURL(ctx.Request.Context())
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":             "server_error",
			"error_description": err.Error(),
		})
		return
	}
	ctx.Redirect(http.StatusFound, authURL)
}

func (c *Client) handleAuthorizationCallback(ctx *gin.Context) {
	if e := ctx.Query("error"); e != "" {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":             e,
			"error_description": ctx.Query("error_description"),
		})
		return
	}
	tok, err := c.exchangeAuthorizationCode(ctx.Request.Context(), ctx.Query("code"), ctx.Query("state"))
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": err.Error(),
		})
		return
	}
	ctx.JSON(http.StatusOK, tok)
}
