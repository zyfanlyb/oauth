package client

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// contextKeyPrincipal gin Context 中存放 AccessPrincipal 的内部键；依赖方请用 CurrentPrincipal 读取。
const contextKeyPrincipal = "oauth_client_principal"

// AuthMiddleware 返回鉴权中间件：按黑白名单决定是否验签，成功则写入 Context。
// 一般由 New 在 EnableAuthMiddleware 开启时自动挂载；也可自行 engine.Use。
// 后续业务接口用 CurrentPrincipal(c) 取当前用户。
func (c *Client) AuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		path := ctx.Request.URL.Path
		if !c.pathNeedsAuth(path) {
			ctx.Next()
			return
		}

		p, err := c.VerifyAccessToken(ctx.Request.Context(), ctx.GetHeader("Authorization"))
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_token",
				"error_description": err.Error(),
			})
			return
		}
		ctx.Set(contextKeyPrincipal, p)
		ctx.Next()
	}
}

// pathNeedsAuth 白名单优先跳过；黑名单为空则其余皆鉴权，非空则仅黑名单鉴权。
func (c *Client) pathNeedsAuth(path string) bool {
	if matchPathList(c.Config.AuthWhitelist, path) {
		return false
	}
	if len(c.Config.AuthBlacklist) == 0 {
		return true
	}
	return matchPathList(c.Config.AuthBlacklist, path)
}

// matchPathList 支持精确匹配，以及以 /* 或 * 结尾的前缀匹配。
func matchPathList(patterns []string, path string) bool {
	for _, pattern := range patterns {
		if pathMatch(pattern, path) {
			return true
		}
	}
	return false
}

func pathMatch(pattern, path string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	if pattern == path {
		return true
	}
	switch {
	case strings.HasSuffix(pattern, "/*"):
		prefix := strings.TrimSuffix(pattern, "/*")
		return path == prefix || strings.HasPrefix(path, prefix+"/")
	case strings.HasSuffix(pattern, "*"):
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(path, prefix)
	default:
		return false
	}
}
