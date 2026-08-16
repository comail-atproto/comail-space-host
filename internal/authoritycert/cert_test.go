package authoritycert

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/comail-atproto/comail-pds-lab/internal/memory"
)

func TestRunProvesImmutableStateCASRecoveryAndTombstone(t *testing.T) {
	did := "did:plc:authoritycert"
	repo := memory.NewBackend().OwnerSession(did)
	report, err := Run(context.Background(), repo, Options{
		RecipientDID: did,
		SpaceKey:     "cert-run-1",
		RunID:        "run-1",
		WorkDir:      filepath.Join(t.TempDir(), "artifacts"),
		Now:          time.Date(2026, 8, 16, 21, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed || report.ProviderID != "memory-v1" || report.TargetSHA256 == "" {
		t.Fatalf("report = %#v", report)
	}
	if !report.Checks.ByteExactReadback || !report.Checks.AtomicMessageState || !report.Checks.ProviderCASConflict ||
		!report.Checks.IdempotentStateRetry || !report.Checks.MailboxMove || !report.Checks.RebuildBeforeDelete || !report.Checks.TombstoneRecovery {
		t.Fatalf("checks = %#v", report.Checks)
	}
	if report.BeforeDelete.Messages != 1 || report.BeforeDelete.Tombstones != 0 || report.AfterDelete.Tombstones != 1 {
		t.Fatalf("projection reports = %#v / %#v", report.BeforeDelete, report.AfterDelete)
	}
}

func TestRunRefusesNonEmptyCertificationSpace(t *testing.T) {
	did := "did:plc:authoritycertreuse"
	repo := memory.NewBackend().OwnerSession(did)
	options := Options{
		RecipientDID: did, SpaceKey: "cert-run-1", RunID: "run-1",
		WorkDir: filepath.Join(t.TempDir(), "first"), Now: time.Now(),
	}
	if _, err := Run(context.Background(), repo, options); err != nil {
		t.Fatal(err)
	}
	options.RunID = "run-2"
	options.WorkDir = filepath.Join(t.TempDir(), "second")
	if _, err := Run(context.Background(), repo, options); err == nil {
		t.Fatal("accepted a non-empty certification space")
	}
}
