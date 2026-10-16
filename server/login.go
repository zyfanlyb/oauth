package server

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

var loginTmpl = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>登录</title>
<style>
  :root { color-scheme: light; }
  body { margin:0; min-height:100vh; display:grid; place-items:center;
         font-family: "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
         background: linear-gradient(160deg, #eef2f7, #d9e2ec 55%, #f7fafc); color:#102a43; }
  .box { width:min(360px, 92vw); padding:28px 24px 24px; background:#fff;
         border:1px solid #d9e2ec; border-radius:12px; box-shadow:0 10px 30px rgba(16,42,67,.08); }
  h1 { margin:0 0 6px; font-size:1.35rem; }
  p { margin:0 0 18px; color:#627d98; font-size:.92rem; }
  label { display:block; margin:0 0 6px; font-size:.85rem; color:#486581; }
  input { width:100%; box-sizing:border-box; margin:0 0 14px; padding:10px 12px;
          border:1px solid #bcccdc; border-radius:8px; font-size:1rem; }
  input:focus { outline:2px solid #829ab1; border-color:#829ab1; }
  button { width:100%; margin-top:4px; padding:11px 12px; border:0; border-radius:8px;
           background:#243b53; color:#fff; font-size:1rem; cursor:pointer; }
  button:hover { background:#102a43; }
  .err { margin:0 0 14px; padding:10px 12px; background:#ffe3e3; color:#c92a2a;
         border-radius:8px; font-size:.9rem; }
  .hint { margin:14px 0 0; color:#829ab1; font-size:.8rem; line-height:1.4; }
</style>
</head>
<body>
  <form class="box" method="post" action="{{.Action}}">
    <h1>登录</h1>
    <p>登录后将返回授权页确认权限</p>
    {{if .Error}}<div class="err">{{.Error}}</div>{{end}}
    <input type="hidden" name="return_to" value="{{.ReturnTo}}"/>
    <label for="username">用户名</label>
    <input id="username" name="username" autocomplete="username" required/>
    <label for="password">密码</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required/>
    <button type="submit">登录</button>
    {{if not .ReturnTo}}<p class="hint">请从客户端发起授权（访问 /oauth/authorize），不要直接打开本页。</p>{{end}}
  </form>
</body>
</html>`))

type loginView struct {
	Action   string
	ReturnTo string
	Error    string
}

// LoginPage 展示登录页。标准流程中由 /oauth/authorize 在未登录时重定向至此。
func (s *Server) LoginPage(c *gin.Context) {
	returnTo := c.Query("return_to")
	if returnTo == "" {
		returnTo = c.Query("return_uri")
	}
	if returnTo != "" && !safeAuthorizeReturn(returnTo) {
		returnTo = ""
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	_ = loginTmpl.Execute(c.Writer, loginView{
		Action:   s.Config.LoginPath,
		ReturnTo: returnTo,
	})
}

// LoginSubmit 处理登录表单：校验账号 → 写会话 Cookie → 跳回授权端点。
func (s *Server) LoginSubmit(c *gin.Context) {
	username := strings.TrimSpace(c.PostForm("username"))
	password := c.PostForm("password")
	returnTo := c.PostForm("return_to")

	renderErr := func(msg string) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Status(http.StatusBadRequest)
		_ = loginTmpl.Execute(c.Writer, loginView{
			Action:   s.Config.LoginPath,
			ReturnTo: returnTo,
			Error:    msg,
		})
	}

	if username == "" || password == "" {
		renderErr("请输入用户名和密码")
		return
	}
	if s.sessions == nil {
		renderErr("会话存储未就绪")
		return
	}

	user, err := s.Users.Authenticate(c.Request.Context(), username, password)
	if err != nil || user == nil || user.Subject == "" {
		renderErr("用户名或密码错误")
		return
	}

	sid, err := randomToken(24)
	if err != nil {
		renderErr("创建会话失败")
		return
	}
	if err := s.sessions.Save(c.Request.Context(), sid, user); err != nil {
		renderErr("保存会话失败")
		return
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     s.Config.SessionCookie,
		Value:    bindOwner(user.Subject, sid),
		Path:     "/",
		MaxAge:   int(s.Config.SessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   s.Config.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})

	// 登录成功必须回到授权端点，由授权端点继续展示同意页并签发 code
	if returnTo == "" || !safeAuthorizeReturn(returnTo) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		_ = loginTmpl.Execute(c.Writer, loginView{
			Action: s.Config.LoginPath,
			Error:  "登录成功，但缺少有效的授权回调。请从客户端重新发起 /oauth/authorize。",
		})
		return
	}
	c.Redirect(http.StatusFound, returnTo)
}

func (s *Server) clearSessionCookie(c *gin.Context) {
	if sid, err := c.Cookie(s.Config.SessionCookie); err == nil && sid != "" && s.sessions != nil {
		_ = s.sessions.Delete(c.Request.Context(), sid)
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     s.Config.SessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.Config.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

// safeAuthorizeReturn 登录后仅允许回到授权端点（相对路径），避免开放重定向。
func safeAuthorizeReturn(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return false
	}
	return u.Path == "/oauth/authorize"
}

// safeReturnTo 登出等场景：仅允许本站相对路径。
func safeReturnTo(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return false
	}
	return strings.HasPrefix(u.Path, "/")
}

func (s *Server) loginURL(returnTo string) string {
	q := url.Values{}
	if returnTo != "" {
		q.Set("return_to", returnTo)
	}
	path := s.Config.LoginPath
	if len(q) == 0 {
		return path
	}
	return path + "?" + q.Encode()
}
