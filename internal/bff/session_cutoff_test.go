// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"testing"
	"time"
)

func TestASessionIssuedBeforeTheCutoffIsEnded(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 5, 2, 0, 0, 0, time.UTC)
	var cutoff time.Time
	clock := now
	s := EndSessionsBefore(NewMemStore(time.Hour), func() time.Time { return cutoff }, nil)
	s.(*cutoffStore).now = func() time.Time { return clock }

	if err := s.Create(ctx, "old", Session{UserID: "u-ada"}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Get(ctx, "old"); !ok {
		t.Fatal("a session was refused with no cutoff set")
	}

	cutoff = now.Add(time.Minute)
	clock = now.Add(2 * time.Minute)
	if err := s.Create(ctx, "new", Session{UserID: "u-ada"}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Get(ctx, "old"); ok {
		t.Fatal("a session issued before the cutoff still works")
	}
	if _, ok, _ := s.Get(ctx, "new"); !ok {
		t.Fatal("a session issued after the cutoff was refused")
	}

	cutoff = time.Time{}
	if _, ok, _ := s.Get(ctx, "old"); ok {
		t.Fatal("the ended session came back: it should have been deleted")
	}
}

func TestASessionWithNoIssueTimeEndsAtAnyCutoff(t *testing.T) {
	ctx := context.Background()
	inner := NewMemStore(time.Hour)
	if err := inner.Create(ctx, "legacy", Session{UserID: "u-ada"}); err != nil {
		t.Fatal(err)
	}
	s := EndSessionsBefore(inner, func() time.Time { return time.Date(2026, 10, 5, 2, 0, 0, 0, time.UTC) }, nil)
	if _, ok, _ := s.Get(ctx, "legacy"); ok {
		t.Fatal("a session stored without an issue time survived the cutoff")
	}
}

func TestSaveKeepsTheIssueTime(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, 10, 5, 1, 0, 0, 0, time.UTC)
	s := EndSessionsBefore(NewMemStore(time.Hour), func() time.Time { return time.Time{} }, nil)
	s.(*cutoffStore).now = func() time.Time { return clock }
	if err := s.Create(ctx, "a", Session{UserID: "u-ada"}); err != nil {
		t.Fatal(err)
	}
	sess, _, _ := s.Get(ctx, "a")
	sess.MFAVerified = true
	if err := s.Save(ctx, "a", sess); err != nil {
		t.Fatal(err)
	}
	got, _, _ := s.Get(ctx, "a")
	if !got.IssuedAt.Equal(clock) {
		t.Fatalf("IssuedAt = %v, want %v", got.IssuedAt, clock)
	}
}
