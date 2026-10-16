package server

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

var consentTmpl = template.Must(template.New("consent").Parse(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>授权确认</title>
<style>
  :root { color-scheme: light; }
  body { margin:0; min-height:100vh; display:grid; place-items:center;
         font-family: "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
         background: linear-gradient(160deg, #eef2f7, #d9e2ec 55%, #f7fafc); color:#102a43; }
  .box { width:min(400px, 92vw); padding:28px 24px 24px; background:#fff;
         border:1px solid #d9e2ec; border-radius:12px; box-shadow:0 10px 30px rgba(16,42,67,.08); }
  h1 { margin:0 0 6px; font-size:1.35rem; }
  p { margin:0 0 14px; color:#627d98; font-size:.92rem; }
  .client { margin:0 0 16px; padding:12px; background:#f0f4f8; border-radius:8px; font-size:.95rem; }
  .client strong { color:#102a43; word-break:break-all; }
  ul { margin:0 0 20px; padding-left:1.2em; color:#486581; font-size:.9rem; }
  .actions { display:flex; gap:10px; }
  button { flex:1; padding:11px 12px; border:0; border-radius:8px; font-size:1rem; cursor:pointer; }
  .approve { background:#243b53; color:#fff; }
  .approve:hover { background:#102a43; }
  .deny { background:#fff; color:#486581; border:1px solid #bcccdc; }
  .deny:hover { background:#f0f4f8; }
  .user { margin:0 0 16px; font-size:.85rem; color:#627d98; }
</style>
</head>
<body>
  <form class="box" method="post" action="{{.Action}}">
    <h1>授权确认</h1>
    <p>应用请求访问你的账号</p>
    <div class="client">应用：<strong>{{.ClientID}}</strong></div>
    {{if .UserLabel}}<div class="user">当前用户：{{.UserLabel}}</div>{{end}}
    {{if .Scopes}}
    <p style="margin-bottom:6px">将获得以下权限：</p>
    <ul>
      {{range .Scopes}}<li>{{.}}</li>{{end}}
    </ul>
    {{else}}
    <p>未指定额外权限范围</p>
    {{end}}
    <input type="hidden" name="response_type" value="{{.ResponseType}}"/>
    <input type="hidden" name="client_id" value="{{.ClientID}}"/>
    <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}"/>
    <input type="hidden" name="scope" value="{{.Scope}}"/>
    <input type="hidden" name="state" value="{{.State}}"/>
    <input type="hidden" name="nonce" value="{{.Nonce}}"/>
    <input type="hidden" name="code_challenge" value="{{.CodeChallenge}}"/>
    <input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}"/>
    <div class="actions">
      <button class="deny" type="submit" name="decision" value="deny">拒绝</button>
      <button class="approve" type="submit" name="decision" value="approve">同意授权</button>
    </div>
  </form>
</body>
</html>`))

type consentView struct {
	Action              string
	ClientID            string
	UserLabel           string
	Scopes              []string
	ResponseType        string
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// ConsentSubmit 处理用户同意/拒绝授权，签发授权码或返回 access_denied。
func (s *Server) ConsentSubmit(c *gin.Context) {
	cfg := s.Config.withDefaults()
	_ = c.Request.ParseForm()

	req := authRequestFromForm(c)
	decision := c.PostForm("decision")

	client, err := s.Clients.Get(c.Request.Context(), req.ClientID)
	if err != nil || client == nil {
		oauthErrorJSON(c, http.StatusBadRequest, "invalid_client", "unknown client_id")
		return
	}
	if errMsg := validateAuthRequest(cfg, client, req); errMsg != "" {
		if req.RedirectURI != "" && validRedirectURI(client, req.RedirectURI) {
			redirectOAuthError(c, req.RedirectURI, "invalid_request", errMsg, req.State)
			return
		}
		oauthErrorJSON(c, http.StatusBadRequest, "invalid_request", errMsg)
		return
	}

	user, err := s.CurrentSessionUser(c)
	if err != nil {
		oauthErrorJSON(c, http.StatusInternalServerError, "server_error", "failed to resolve current user")
		return
	}
	if user == nil || user.Subject == "" {
		c.Redirect(http.StatusFound, s.loginURL(s.authorizeURL(req)))
		return
	}

	if decision != "approve" {
		redirectOAuthError(c, req.RedirectURI, "access_denied", "the resource owner denied the request", req.State)
		return
	}

	if err := s.issueCodeAndRedirect(c, cfg, user, req); err != nil {
		redirectOAuthError(c, req.RedirectURI, "server_error", err.Error(), req.State)
	}
}

func (s *Server) renderConsent(c *gin.Context, user *UserClaims, req authRequest) {
	scopes := strings.Fields(req.Scope)
	labels := make([]string, 0, len(scopes))
	for _, sc := range scopes {
		labels = append(labels, scopeLabel(sc))
	}
	userLabel := user.Subject
	if user.Name != "" {
		userLabel = user.Name + " (" + user.Subject + ")"
	} else if user.Email != "" {
		userLabel = user.Email
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	_ = consentTmpl.Execute(c.Writer, consentView{
		Action:              s.Config.ConsentPath,
		ClientID:            req.ClientID,
		UserLabel:           userLabel,
		Scopes:              labels,
		ResponseType:        req.ResponseType,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
	})
}

func (s *Server) issueCodeAndRedirect(c *gin.Context, cfg Config, user *UserClaims, req authRequest) error {
	code, err := randomToken(32)
	if err != nil {
		return err
	}
	method := req.CodeChallengeMethod
	if req.CodeChallenge != "" && method == "" {
		method = "plain"
	}
	authCode := &AuthCode{
		Code:                code,
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Subject:             user.Subject,
		Scope:               req.Scope,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: method,
		ExpiresAt:           time.Now().Add(cfg.AuthCodeTTL),
	}
	if err := s.Codes.Save(c.Request.Context(), authCode); err != nil {
		return err
	}

	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		return err
	}
	vals := u.Query()
	vals.Set("code", code)
	if req.State != "" {
		vals.Set("state", req.State)
	}
	u.RawQuery = vals.Encode()
	c.Redirect(http.StatusFound, u.String())
	return nil
}

func scopeLabel(scope string) string {
	switch scope {
	case "openid":
		return "验证你的身份 (openid)"
	case "profile":
		return "读取你的基本资料 (profile)"
	case "email":
		return "读取你的邮箱 (email)"
	case "offline_access":
		return "在你离线时保持访问 (offline_access)"
	default:
		return scope
	}
}
