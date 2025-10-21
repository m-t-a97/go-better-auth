package cached

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/m-t-a97/go-better-auth/domain/session"
	"github.com/m-t-a97/go-better-auth/repository/memory"
	"github.com/m-t-a97/go-better-auth/storage"
)

func TestCachedSessionRepository_Create(t *testing.T) {
	primary := memory.NewSessionRepository()
	secondary := storage.NewMemorySecondaryStorage()
	repo := NewSessionRepository(primary, secondary)

	sess := &session.Session{
		ID:        uuid.New().String(),
		UserID:    "user123",
		Token:     "token123",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	err := repo.Create(sess)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify it was stored in primary
	found, err := primary.FindByToken(sess.Token)
	if err != nil {
		t.Fatalf("expected to find session in primary, got error: %v", err)
	}
	if found.Token != sess.Token {
		t.Errorf("expected token %s, got %s", sess.Token, found.Token)
	}
}

func TestCachedSessionRepository_FindByToken_CacheHit(t *testing.T) {
	primary := memory.NewSessionRepository()
	secondary := storage.NewMemorySecondaryStorage()
	repo := NewSessionRepository(primary, secondary)

	sess := &session.Session{
		ID:        uuid.New().String(),
		UserID:    "user123",
		Token:     "token123",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Create session
	if err := repo.Create(sess); err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// First lookup should cache it
	found1, err := repo.FindByToken(sess.Token)
	if err != nil {
		t.Fatalf("expected to find session, got error: %v", err)
	}
	if found1.Token != sess.Token {
		t.Errorf("expected token %s, got %s", sess.Token, found1.Token)
	}

	// Delete from primary storage to verify cache is used
	if err := primary.Delete(sess.ID); err != nil {
		t.Fatalf("failed to delete from primary: %v", err)
	}

	// Second lookup should come from cache
	found2, err := repo.FindByToken(sess.Token)
	if err != nil {
		t.Fatalf("expected to find session in cache, got error: %v", err)
	}
	if found2.Token != sess.Token {
		t.Errorf("expected token %s, got %s", sess.Token, found2.Token)
	}
}

func TestCachedSessionRepository_Delete(t *testing.T) {
	primary := memory.NewSessionRepository()
	secondary := storage.NewMemorySecondaryStorage()
	repo := NewSessionRepository(primary, secondary)

	sess := &session.Session{
		ID:        uuid.New().String(),
		UserID:    "user123",
		Token:     "token123",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Create and cache
	if err := repo.Create(sess); err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Verify it's cached
	_, err := repo.FindByToken(sess.Token)
	if err != nil {
		t.Fatalf("expected to find session, got error: %v", err)
	}

	// Delete
	if err := repo.Delete(sess.ID); err != nil {
		t.Fatalf("failed to delete session: %v", err)
	}

	// Verify it's deleted from primary
	_, err = primary.FindByToken(sess.Token)
	if err == nil {
		t.Error("expected session to be deleted from primary")
	}
}

func TestCachedSessionRepository_Update(t *testing.T) {
	primary := memory.NewSessionRepository()
	secondary := storage.NewMemorySecondaryStorage()
	repo := NewSessionRepository(primary, secondary)

	sess := &session.Session{
		ID:        uuid.New().String(),
		UserID:    "user123",
		Token:     "token123",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Create
	if err := repo.Create(sess); err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Update expiration
	sess.ExpiresAt = time.Now().Add(2 * time.Hour)
	if err := repo.Update(sess); err != nil {
		t.Fatalf("failed to update session: %v", err)
	}

	// Verify cache was updated
	found, err := repo.FindByToken(sess.Token)
	if err != nil {
		t.Fatalf("expected to find session, got error: %v", err)
	}

	// Check that the expiration is close to what we set
	diff := found.ExpiresAt.Sub(sess.ExpiresAt)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("expected expiration around %v, got %v", sess.ExpiresAt, found.ExpiresAt)
	}
}
