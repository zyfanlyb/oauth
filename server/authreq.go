package server

import (
	"net/url"

	"github.com/gin-gonic/gin"
)

// authRequest 授权请求参数（authorize / consent 共用）。
type authRequest struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              string
}

func authRequestFromQuery(c *gin.Context) authRequest {
	q := c.Request.URL.Query()
	return authRequest{
		ResponseType:        q.Get("response_type"),
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		Scope:               q.Get("scope"),
		State:               q.Get("state"),
		Nonce:               q.Get("nonce"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		Prompt:              q.Get("prompt"),
	}
}

func authRequestFromForm(c *gin.Context) authRequest {
	return authRequest{
		ResponseType:        c.PostForm("response_type"),
		ClientID:            c.PostForm("client_id"),
		RedirectURI:         c.PostForm("redirect_uri"),
		Scope:               c.PostForm("scope"),
		State:               c.PostForm("state"),
		Nonce:               c.PostForm("nonce"),
		CodeChallenge:       c.PostForm("code_challenge"),
		CodeChallengeMethod: c.PostForm("code_challenge_method"),
	}
}

// validateAuthRequest 在 redirect_uri 已通过白名单校验后调用；返回非空则为错误描述。
func validateAuthRequest(cfg Config, client *Client, req authRequest) string {
	if req.ResponseType != "code" {
		return "only response_type=code is supported"
	}
	if cfg.RequirePKCE && req.CodeChallenge == "" {
		return "code_challenge is required"
	}
	if req.CodeChallenge != "" {
		method := req.CodeChallengeMethod
		if method == "" {
			method = "plain"
		}
		if method != "S256" && method != "plain" {
			return "unsupported code_challenge_method"
		}
	}
	if req.Scope != "" && len(client.Scopes) > 0 && !scopesAllowed(client.Scopes, req.Scope) {
		return "requested scope is not allowed"
	}
	return ""
}

func (s *Server) authorizeURL(req authRequest) string {
	q := url.Values{}
	q.Set("response_type", req.ResponseType)
	q.Set("client_id", req.ClientID)
	q.Set("redirect_uri", req.RedirectURI)
	if req.Scope != "" {
		q.Set("scope", req.Scope)
	}
	if req.State != "" {
		q.Set("state", req.State)
	}
	if req.Nonce != "" {
		q.Set("nonce", req.Nonce)
	}
	if req.CodeChallenge != "" {
		q.Set("code_challenge", req.CodeChallenge)
	}
	if req.CodeChallengeMethod != "" {
		q.Set("code_challenge_method", req.CodeChallengeMethod)
	}
	if req.Prompt != "" {
		q.Set("prompt", req.Prompt)
	}
	return "/oauth/authorize?" + q.Encode()
}

func hasPrompt(prompts []string, want string) bool {
	for _, p := range prompts {
		if p == want {
			return true
		}
	}
	return false
}
