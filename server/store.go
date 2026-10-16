package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

func storeKey(prefix, kind, id string) string {
	if prefix == "" {
		prefix = "oauth"
	}
	return prefix + ":" + kind + ":" + id
}

func tokenKeyID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ownerSegment 把用户 sub 或客户端 id 放进 Redis 键。
func ownerSegment(owner string) string {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return "_"
	}
	return strings.NewReplacer(":", "_", " ", "_", "*", "_").Replace(owner)
}

func accessKey(prefix, owner, token string) string {
	return prefix + ":access:" + ownerSegment(owner) + ":" + tokenKeyID(token)
}

func refreshKey(prefix, token string) string {
	return prefix + ":refresh:" + tokenKeyID(token)
}

func sessionKey(prefix, owner, sid string) string {
	return prefix + ":session:" + ownerSegment(owner) + ":" + sid
}

// bindOwner 把主体标识放进会话 Cookie，查询时直接拆出来。
func bindOwner(owner, id string) string {
	return ownerSegment(owner) + ":" + id
}

func splitOwner(raw string) (owner, id string, ok bool) {
	owner, id, ok = strings.Cut(raw, ":")
	if !ok || owner == "" || id == "" || strings.Contains(id, ":") {
		return "", "", false
	}
	return owner, id, true
}

// jwtStringClaim 读取 JWT payload 中的明文字段（不验签，仅用于拼 Redis 键）。
func jwtStringClaim(token, name string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return ""
	}
	v, _ := claims[name].(string)
	return v
}

func accessOwner(token string) string {
	if sub := jwtStringClaim(token, "sub"); sub != "" {
		return sub
	}
	return jwtStringClaim(token, "client_id")
}

// ---------- 授权码 ----------

type codeStore struct {
	rdb    *redis.Client
	prefix string
}

func newCodeStore(rdb *redis.Client, prefix string) *codeStore {
	return &codeStore{rdb: rdb, prefix: prefix}
}

func (s *codeStore) Save(ctx context.Context, code *AuthCode) error {
	b, err := json.Marshal(code)
	if err != nil {
		return err
	}
	ttl := time.Until(code.ExpiresAt)
	if ttl <= 0 {
		ttl = time.Minute
	}
	return s.rdb.Set(ctx, storeKey(s.prefix, "code", code.Code), string(b), ttl).Err()
}

func (s *codeStore) Take(ctx context.Context, code string) (*AuthCode, error) {
	key := storeKey(s.prefix, "code", code)
	raw, err := s.rdb.Get(ctx, key).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = s.rdb.Del(ctx, key).Err()
	var out AuthCode
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---------- 令牌 ----------

type tokenStore struct {
	rdb    *redis.Client
	prefix string
}

func newTokenStore(rdb *redis.Client, prefix string) *tokenStore {
	return &tokenStore{rdb: rdb, prefix: prefix}
}

func (s *tokenStore) SaveAccess(ctx context.Context, t *AccessToken) error {
	b, err := json.Marshal(t)
	if err != nil {
		return err
	}
	ttl := time.Until(t.ExpiresAt)
	if ttl <= 0 {
		ttl = time.Minute
	}
	return s.rdb.Set(ctx, accessKey(s.prefix, t.Subject, t.Token), string(b), ttl).Err()
}

func (s *tokenStore) SaveRefresh(ctx context.Context, t *RefreshToken) error {
	b, err := json.Marshal(t)
	if err != nil {
		return err
	}
	ttl := time.Until(t.ExpiresAt)
	if ttl <= 0 {
		ttl = time.Minute
	}
	return s.rdb.Set(ctx, refreshKey(s.prefix, t.Token), string(b), ttl).Err()
}

func (s *tokenStore) GetAccess(ctx context.Context, token string) (*AccessToken, error) {
	raw, err := s.rdb.Get(ctx, accessKey(s.prefix, accessOwner(token), token)).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out AccessToken
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *tokenStore) GetRefresh(ctx context.Context, token string) (*RefreshToken, error) {
	raw, err := s.rdb.Get(ctx, refreshKey(s.prefix, token)).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out RefreshToken
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *tokenStore) RevokeAccess(ctx context.Context, token string) error {
	at, err := s.GetAccess(ctx, token)
	if err != nil {
		return err
	}
	if at != nil && at.RefreshToken != "" {
		if err := s.RevokeRefresh(ctx, at.RefreshToken); err != nil {
			return err
		}
	}
	return s.rdb.Del(ctx, accessKey(s.prefix, accessOwner(token), token)).Err()
}

func (s *tokenStore) RevokeRefresh(ctx context.Context, token string) error {
	return s.rdb.Del(ctx, refreshKey(s.prefix, token)).Err()
}

// ---------- 登录会话 ----------

type sessionData struct {
	User UserClaims `json:"user"`
}

type sessionStore struct {
	rdb    *redis.Client
	prefix string
	ttl    time.Duration
}

func newSessionStore(rdb *redis.Client, prefix string, ttl time.Duration) *sessionStore {
	return &sessionStore{rdb: rdb, prefix: prefix, ttl: ttl}
}

func (s *sessionStore) Save(ctx context.Context, sid string, user *UserClaims) error {
	b, err := json.Marshal(sessionData{User: *user})
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, sessionKey(s.prefix, user.Subject, sid), string(b), s.ttl).Err()
}

func (s *sessionStore) Get(ctx context.Context, cookie string) (*UserClaims, error) {
	owner, sid, ok := splitOwner(cookie)
	if !ok {
		return nil, nil
	}
	raw, err := s.rdb.Get(ctx, sessionKey(s.prefix, owner, sid)).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var data sessionData
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return nil, err
	}
	if data.User.Subject == "" {
		return nil, nil
	}
	return &data.User, nil
}

func (s *sessionStore) Delete(ctx context.Context, cookie string) error {
	owner, sid, ok := splitOwner(cookie)
	if !ok {
		return nil
	}
	return s.rdb.Del(ctx, sessionKey(s.prefix, owner, sid)).Err()
}
