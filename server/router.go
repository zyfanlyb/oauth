package server

import (
	"github.com/gin-gonic/gin"
)

// registerRoutes 挂载 OAuth / OIDC 端点与登录页（由 New 调用）。
func (s *Server) registerRoutes(engine *gin.Engine) {
	if s.sessions == nil {
		s.initStores()
	}
	// 登录 / 同意页路径固定，与 group 内注册保持一致
	s.Config.LoginPath = "/oauth/login"
	s.Config.ConsentPath = "/oauth/consent"

	// 授权服务器元数据：返回端点地址、支持的授权类型等配置信息
	engine.GET("/.well-known/oauth-authorization-server", s.Metadata)

	// OIDC 发现文档：客户端据此自动发现授权/令牌等端点
	engine.GET("/.well-known/openid-configuration", s.OpenIDConfiguration)

	oauth := engine.Group("/oauth")
	{
		// 登录鉴权页（由 /oauth/authorize 在未登录时重定向至此）
		oauth.GET("/login", s.LoginPage)
		oauth.POST("/login", s.LoginSubmit)
		oauth.GET("/logout", s.Logout)
		oauth.POST("/logout", s.Logout)

		// 用户同意页（由 /oauth/authorize 在已登录后展示；表单提交到此）
		oauth.POST("/consent", s.ConsentSubmit)

		// 授权端点：协议入口 → 登录 → 同意 → 返回授权码
		oauth.GET("/authorize", s.Authorize)

		// 令牌端点：用授权码换取 access_token / refresh_token，或刷新令牌
		oauth.POST("/token", s.Token)

		// 撤销端点：使 access_token 或 refresh_token 失效
		oauth.POST("/revoke", s.Revoke)

		// 检视端点：查询令牌是否有效及其归属、作用域等信息
		oauth.POST("/introspect", s.Introspect)

		// 用户信息端点：凭 access_token 获取当前用户的身份声明
		oauth.GET("/userinfo", s.UserInfo)
		oauth.POST("/userinfo", s.UserInfo)

		// 公钥集：RS256 公钥（JWKS），业务系统据此验签 access_token / id_token
		oauth.GET("/jwks", s.JWKS)
	}
}
