// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	bredis "github.com/Bugs5382/go-redis"
)

// OAuthStore holds registered clients, parked authorization requests and
// one-time codes. Take must be atomic so a code can be redeemed only once.
type OAuthStore interface {
	Put(ctx context.Context, key string, v any, ttl time.Duration) error
	Get(ctx context.Context, key string, out any) (bool, error)
	Take(ctx context.Context, key string, out any) (bool, error)
}

type memOAuthStore struct {
	mu   sync.Mutex
	data map[string][]byte
}

func NewMemOAuthStore() OAuthStore { return &memOAuthStore{data: map[string][]byte{}} }

func (m *memOAuthStore) Put(_ context.Context, key string, v any, _ time.Duration) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = b
	return nil
}

func (m *memOAuthStore) Get(_ context.Context, key string, out any) (bool, error) {
	m.mu.Lock()
	b, ok := m.data[key]
	m.mu.Unlock()
	if !ok {
		return false, nil
	}
	return true, json.Unmarshal(b, out)
}

func (m *memOAuthStore) Take(_ context.Context, key string, out any) (bool, error) {
	m.mu.Lock()
	b, ok := m.data[key]
	delete(m.data, key)
	m.mu.Unlock()
	if !ok {
		return false, nil
	}
	return true, json.Unmarshal(b, out)
}

type redisOAuthStore struct {
	rdb    bredis.UniversalClient
	prefix string
}

func NewRedisOAuthStore(c *bredis.Client) OAuthStore {
	return &redisOAuthStore{rdb: c.Redis(), prefix: "sneakers:oauth:"}
}

func (s *redisOAuthStore) Put(ctx context.Context, key string, v any, ttl time.Duration) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, s.prefix+key, b, ttl).Err()
}

func (s *redisOAuthStore) Get(ctx context.Context, key string, out any) (bool, error) {
	b, err := s.rdb.Get(ctx, s.prefix+key).Bytes()
	if errors.Is(err, bredis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(b, out)
}

func (s *redisOAuthStore) Take(ctx context.Context, key string, out any) (bool, error) {
	b, err := s.rdb.GetDel(ctx, s.prefix+key).Bytes()
	if errors.Is(err, bredis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(b, out)
}
