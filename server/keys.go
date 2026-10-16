package server

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zyfanlyb/util/common"
)

// Redis 中密钥包结构（含私钥 PEM，仅认证中心可读）。
type keyBundle struct {
	CurrentKID string     `json:"current_kid"`
	Keys       []storedKey `json:"keys"`
}

type storedKey struct {
	KID        string `json:"kid"`
	PrivatePEM string `json:"private_pem"`
	CreatedAt  int64  `json:"created_at"` // unix 秒
}

func (s *Server) keysRedisKey() string {
	return storeKey(s.Config.RedisKeyPrefix, "keystore", "bundle")
}

func (s *Server) keysLockKey() string {
	return storeKey(s.Config.RedisKeyPrefix, "keystore", "lock")
}

// ensureKeys 从 Redis 加载密钥；没有则生成；到期则轮换。
func (s *Server) ensureKeys(ctx context.Context) error {
	if s.Redis == nil {
		return errors.New("redis not configured")
	}
	bundle, err := s.loadKeyBundle(ctx)
	if err != nil {
		return err
	}
	now := time.Now()

	if bundle == nil || len(bundle.Keys) == 0 {
		return s.withKeyLock(ctx, func() error {
			again, err := s.loadKeyBundle(ctx)
			if err != nil {
				return err
			}
			if again != nil && len(again.Keys) > 0 {
				s.cacheBundle(again)
				return nil
			}
			ks, err := common.NewKeyStore()
			if err != nil {
				return err
			}
			sk, err := keyStoreToStored(ks, now)
			if err != nil {
				return err
			}
			b := &keyBundle{CurrentKID: sk.KID, Keys: []storedKey{sk}}
			if err := s.saveKeyBundle(ctx, b); err != nil {
				return err
			}
			s.cacheBundle(b)
			return nil
		})
	}

	s.cacheBundle(bundle)
	cur := bundle.find(bundle.CurrentKID)
	needRotate := s.Config.KeyRotateEvery > 0 && cur != nil &&
		now.Sub(time.Unix(cur.CreatedAt, 0)) >= s.Config.KeyRotateEvery

	if needRotate {
		_ = s.withKeyLock(ctx, func() error {
			again, err := s.loadKeyBundle(ctx)
			if err != nil || again == nil {
				return err
			}
			cur = again.find(again.CurrentKID)
			if cur == nil || now.Sub(time.Unix(cur.CreatedAt, 0)) < s.Config.KeyRotateEvery {
				s.cacheBundle(again)
				return nil
			}
			ks, err := common.NewKeyStore()
			if err != nil {
				return err
			}
			sk, err := keyStoreToStored(ks, now)
			if err != nil {
				return err
			}
			again.CurrentKID = sk.KID
			again.Keys = append(again.Keys, sk)
			again.Keys = pruneKeys(again.Keys, again.CurrentKID, now, s.Config.KeyRetainFor)
			if err := s.saveKeyBundle(ctx, again); err != nil {
				return err
			}
			s.cacheBundle(again)
			return nil
		})
	} else if s.Config.KeyRetainFor > 0 {
		pruned := pruneKeys(bundle.Keys, bundle.CurrentKID, now, s.Config.KeyRetainFor)
		if len(pruned) != len(bundle.Keys) {
			bundle.Keys = pruned
			_ = s.saveKeyBundle(ctx, bundle)
			s.cacheBundle(bundle)
		}
	}
	return nil
}

func (s *Server) withKeyLock(ctx context.Context, fn func() error) error {
	ok, err := s.Redis.SetNX(ctx, s.keysLockKey(), "1", 10*time.Second).Result()
	if err != nil {
		return err
	}
	if !ok {
		// 其他实例正在轮换，稍等再读
		time.Sleep(50 * time.Millisecond)
		b, err := s.loadKeyBundle(ctx)
		if err != nil {
			return err
		}
		if b != nil {
			s.cacheBundle(b)
		}
		return nil
	}
	defer s.Redis.Del(ctx, s.keysLockKey())
	return fn()
}

func (s *Server) loadKeyBundle(ctx context.Context) (*keyBundle, error) {
	raw, err := s.Redis.Get(ctx, s.keysRedisKey()).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var b keyBundle
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		return nil, err
	}
	return &b, nil
}

func (s *Server) saveKeyBundle(ctx context.Context, b *keyBundle) error {
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	return s.Redis.Set(ctx, s.keysRedisKey(), string(raw), 0).Err()
}

func (s *Server) cacheBundle(b *keyBundle) {
	s.keyMu.Lock()
	s.keyCache = b
	s.keyMu.Unlock()
}

func (s *Server) cachedBundle() *keyBundle {
	s.keyMu.RLock()
	defer s.keyMu.RUnlock()
	return s.keyCache
}

func (b *keyBundle) find(kid string) *storedKey {
	if b == nil {
		return nil
	}
	for i := range b.Keys {
		if b.Keys[i].KID == kid {
			return &b.Keys[i]
		}
	}
	return nil
}

func pruneKeys(keys []storedKey, currentKID string, now time.Time, retain time.Duration) []storedKey {
	if retain <= 0 {
		// 至少保留当前钥
		for _, k := range keys {
			if k.KID == currentKID {
				return []storedKey{k}
			}
		}
		return keys
	}
	out := make([]storedKey, 0, len(keys))
	for _, k := range keys {
		if k.KID == currentKID || now.Sub(time.Unix(k.CreatedAt, 0)) <= retain {
			out = append(out, k)
		}
	}
	return out
}

func keyStoreToStored(ks *common.KeyStore, at time.Time) (storedKey, error) {
	if ks == nil || ks.Private == nil {
		return storedKey{}, errors.New("empty keystore")
	}
	der := x509.MarshalPKCS1PrivateKey(ks.Private)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	return storedKey{
		KID:        ks.KID,
		PrivatePEM: string(pemBytes),
		CreatedAt:  at.Unix(),
	}, nil
}

func storedToKeyStore(sk storedKey) (*common.KeyStore, error) {
	block, _ := pem.Decode([]byte(sk.PrivatePEM))
	if block == nil {
		return nil, errors.New("invalid private pem")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &common.KeyStore{
		KID:     sk.KID,
		Private: priv,
		Public:  &priv.PublicKey,
	}, nil
}

// signingKey 返回当前用于签发的密钥。
func (s *Server) signingKey(ctx context.Context) (*common.KeyStore, error) {
	if err := s.ensureKeys(ctx); err != nil {
		return nil, err
	}
	b := s.cachedBundle()
	if b == nil {
		return nil, errors.New("keystore empty")
	}
	sk := b.find(b.CurrentKID)
	if sk == nil {
		return nil, fmt.Errorf("current kid %q not found", b.CurrentKID)
	}
	return storedToKeyStore(*sk)
}

// buildJWKS 返回仍在保留期内的公钥集。
func (s *Server) buildJWKS(ctx context.Context) (common.JWKS, error) {
	if err := s.ensureKeys(ctx); err != nil {
		return common.JWKS{}, err
	}
	b := s.cachedBundle()
	if b == nil {
		return common.JWKS{Keys: []common.JWK{}}, nil
	}
	keys := make([]common.JWK, 0, len(b.Keys))
	for _, sk := range b.Keys {
		ks, err := storedToKeyStore(sk)
		if err != nil {
			continue
		}
		keys = append(keys, common.JWK{
			Kty: "RSA",
			Use: "sig",
			Alg: common.AlgRS256,
			Kid: ks.KID,
			N:   base64.RawURLEncoding.EncodeToString(ks.Public.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(ks.Public.E)).Bytes()),
		})
	}
	return common.JWKS{Keys: keys}, nil
}

// publicKeyForToken 按 JWT header.kid 取公钥。
func (s *Server) publicKeyForToken(ctx context.Context, token string) (*rsa.PublicKey, error) {
	jwks, err := s.buildJWKS(ctx)
	if err != nil {
		return nil, err
	}
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
