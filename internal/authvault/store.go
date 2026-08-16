package authvault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/bluesky-social/indigo/atproto/auth/oauth"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"golang.org/x/sys/unix"
)

var (
	ErrNotFound      = errors.New("authvault: item not found")
	ErrAlreadyExists = errors.New("authvault: item already exists")
	ErrDecrypt       = errors.New("authvault: decrypt failed")
	ErrPermissions   = errors.New("authvault: insecure permissions")
)

const (
	formatVersion  = 2
	keyBytes       = 32
	maxVaultBytes  = 8 * 1024 * 1024
	authRequestTTL = 15 * time.Minute
)

var magic = []byte("CMPDSV02")

type diskState struct {
	Version  int                                `json:"version"`
	Sessions map[string]oauth.ClientSessionData `json:"sessions"`
	Requests map[string]storedAuthRequest       `json:"requests"`
}

type storedAuthRequest struct {
	Data    oauth.AuthRequestData `json:"data"`
	SavedAt string                `json:"savedAt"`
}

type Store struct {
	mu        sync.Mutex
	vaultPath string
	keyPath   string
	lockPath  string
	key       []byte
	now       func() time.Time
}

var _ oauth.ClientAuthStore = (*Store)(nil)

// Create initializes a new encrypted OAuth vault and a separate 256-bit key.
// Both files are create-only and mode 0600. The containing directory must not
// be accessible by group or other users.
func Create(vaultPath, keyPath string) (*Store, error) {
	if err := validatePaths(vaultPath, keyPath); err != nil {
		return nil, err
	}
	if err := ensurePrivateParent(vaultPath); err != nil {
		return nil, err
	}
	if filepath.Dir(vaultPath) != filepath.Dir(keyPath) {
		if err := ensurePrivateParent(keyPath); err != nil {
			return nil, err
		}
	}
	if err := writeNewKey(keyPath); err != nil {
		return nil, err
	}
	key, err := readKey(keyPath)
	if err != nil {
		return nil, err
	}
	store := &Store{vaultPath: vaultPath, keyPath: keyPath, lockPath: vaultPath + ".lock", key: key, now: time.Now}
	state := newDiskState()
	if err := store.withLock(context.Background(), func() error {
		if _, err := os.Lstat(vaultPath); err == nil {
			return os.ErrExist
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return store.writeLocked(state)
	}); err != nil {
		_ = os.Remove(keyPath)
		return nil, err
	}
	return store, nil
}

// Open validates permissions and decrypts the vault once before returning.
func Open(vaultPath, keyPath string) (*Store, error) {
	if err := validatePaths(vaultPath, keyPath); err != nil {
		return nil, err
	}
	if err := requirePrivateRegular(vaultPath); err != nil {
		return nil, err
	}
	key, err := readKey(keyPath)
	if err != nil {
		return nil, err
	}
	store := &Store{vaultPath: vaultPath, keyPath: keyPath, lockPath: vaultPath + ".lock", key: key, now: time.Now}
	if err := store.withLock(context.Background(), func() error {
		_, err := store.readLocked()
		return err
	}); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *Store) GetSession(ctx context.Context, did syntax.DID, sessionID string) (*oauth.ClientSessionData, error) {
	var out oauth.ClientSessionData
	err := s.read(ctx, func(state diskState) error {
		value, ok := state.Sessions[sessionKey(did, sessionID)]
		if !ok {
			return ErrNotFound
		}
		out = value
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *Store) SaveSession(ctx context.Context, session oauth.ClientSessionData) error {
	if session.AccountDID == "" || session.SessionID == "" {
		return errors.New("authvault: session DID and ID are required")
	}
	return s.mutate(ctx, func(state *diskState) error {
		state.Sessions[sessionKey(session.AccountDID, session.SessionID)] = session
		return nil
	})
}

func (s *Store) DeleteSession(ctx context.Context, did syntax.DID, sessionID string) error {
	return s.mutate(ctx, func(state *diskState) error {
		delete(state.Sessions, sessionKey(did, sessionID))
		return nil
	})
}

func (s *Store) GetAuthRequestInfo(ctx context.Context, stateID string) (*oauth.AuthRequestData, error) {
	var out oauth.AuthRequestData
	err := s.read(ctx, func(state diskState) error {
		value, ok := state.Requests[stateID]
		if !ok {
			return ErrNotFound
		}
		savedAt, err := time.Parse(time.RFC3339Nano, value.SavedAt)
		if err != nil || !savedAt.Add(authRequestTTL).After(s.now().UTC()) {
			return ErrNotFound
		}
		out = value.Data
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *Store) SaveAuthRequestInfo(ctx context.Context, info oauth.AuthRequestData) error {
	if info.State == "" {
		return errors.New("authvault: request state is required")
	}
	return s.mutate(ctx, func(state *diskState) error {
		s.pruneExpired(state)
		if _, ok := state.Requests[info.State]; ok {
			return ErrAlreadyExists
		}
		state.Requests[info.State] = storedAuthRequest{Data: info, SavedAt: s.now().UTC().Format(time.RFC3339Nano)}
		return nil
	})
}

func (s *Store) DeleteAuthRequestInfo(ctx context.Context, stateID string) error {
	return s.mutate(ctx, func(state *diskState) error {
		delete(state.Requests, stateID)
		return nil
	})
}

func (s *Store) read(ctx context.Context, use func(diskState) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.withLock(ctx, func() error {
		state, err := s.readLocked()
		if err != nil {
			return err
		}
		return use(state)
	})
}

func (s *Store) mutate(ctx context.Context, change func(*diskState) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.withLock(ctx, func() error {
		state, err := s.readLocked()
		if err != nil {
			return err
		}
		if err := change(&state); err != nil {
			return err
		}
		return s.writeLocked(state)
	})
}

func (s *Store) withLock(ctx context.Context, fn func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	lock, err := os.OpenFile(s.lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := requirePrivateFile(lock); err != nil {
		return err
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return err
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN) //nolint:errcheck
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn()
}

func (s *Store) readLocked() (diskState, error) {
	if err := requirePrivateRegular(s.vaultPath); err != nil {
		return diskState{}, err
	}
	data, err := os.ReadFile(s.vaultPath)
	if err != nil {
		return diskState{}, err
	}
	if len(data) > maxVaultBytes || len(data) < len(magic)+12+16 || !equalBytes(data[:len(magic)], magic) {
		return diskState{}, ErrDecrypt
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return diskState{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return diskState{}, err
	}
	nonceStart := len(magic)
	nonceEnd := nonceStart + aead.NonceSize()
	if len(data) < nonceEnd+aead.Overhead() {
		return diskState{}, ErrDecrypt
	}
	plaintext, err := aead.Open(nil, data[nonceStart:nonceEnd], data[nonceEnd:], magic)
	if err != nil {
		return diskState{}, ErrDecrypt
	}
	var state diskState
	if err := json.Unmarshal(plaintext, &state); err != nil || state.Version != formatVersion || state.Sessions == nil || state.Requests == nil {
		return diskState{}, ErrDecrypt
	}
	return state, nil
}

func (s *Store) writeLocked(state diskState) error {
	plaintext, err := json.Marshal(state)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, magic)
	data := make([]byte, 0, len(magic)+len(nonce)+len(ciphertext))
	data = append(data, magic...)
	data = append(data, nonce...)
	data = append(data, ciphertext...)
	if len(data) > maxVaultBytes {
		return errors.New("authvault: encrypted vault exceeds safety bound")
	}
	parent := filepath.Dir(s.vaultPath)
	tmp, err := os.CreateTemp(parent, ".oauth-vault-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, s.vaultPath); err != nil {
		return err
	}
	dir, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func newDiskState() diskState {
	return diskState{Version: formatVersion, Sessions: map[string]oauth.ClientSessionData{}, Requests: map[string]storedAuthRequest{}}
}

func (s *Store) pruneExpired(state *diskState) {
	now := s.now().UTC()
	for stateID, request := range state.Requests {
		savedAt, err := time.Parse(time.RFC3339Nano, request.SavedAt)
		if err != nil || !savedAt.Add(authRequestTTL).After(now) {
			delete(state.Requests, stateID)
		}
	}
}

func sessionKey(did syntax.DID, sessionID string) string { return did.String() + "\x00" + sessionID }

func validatePaths(vaultPath, keyPath string) error {
	if vaultPath == "" || keyPath == "" || vaultPath == keyPath || !filepath.IsAbs(vaultPath) || !filepath.IsAbs(keyPath) {
		return errors.New("authvault: distinct absolute vault and key paths are required")
	}
	return nil
}

func ensurePrivateParent(path string) error {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	info, err := os.Stat(parent)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: directory %s must be mode 0700 or stricter", ErrPermissions, parent)
	}
	return nil
}

func writeNewKey(path string) error {
	key := make([]byte, keyBytes)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(key); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	return file.Close()
}

func readKey(path string) ([]byte, error) {
	if err := requirePrivateRegular(path); err != nil {
		return nil, err
	}
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(key) != keyBytes {
		return nil, errors.New("authvault: key must contain exactly 32 bytes")
	}
	return key, nil
}

func requirePrivateRegular(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return requirePrivateFile(file)
}

func requirePrivateFile(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: %s must be a private regular file", ErrPermissions, file.Name())
	}
	return nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
