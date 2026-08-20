package authoritycert

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/comail-atproto/comail-space-host/internal/memory"
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
		!report.Checks.IdempotentStateRetry || !report.Checks.MailboxMove || !report.Checks.SourceVersionReplacement ||
		!report.Checks.RebuildBeforeDelete || !report.Checks.TombstoneRecovery {
		t.Fatalf("checks = %#v", report.Checks)
	}
	if report.BeforeDelete.Messages != 2 || report.BeforeDelete.Tombstones != 1 || report.AfterDelete.Tombstones != 2 {
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

func TestLoadEvidenceBindsOwnerOnlyReportToExactProviderEpoch(t *testing.T) {
	did := "did:plc:authoritycertevidence"
	repo := memory.NewBackend().OwnerSession(did)
	options := Options{
		RecipientDID: did, SpaceKey: "cert-run-evidence", RunID: "evidence-run",
		WorkDir: filepath.Join(t.TempDir(), "artifacts"), Now: time.Now(),
	}
	report, err := Run(context.Background(), repo, options)
	if err != nil {
		t.Fatal(err)
	}
	target, err := repo.EnsureMailbox(context.Background(), did, options.SpaceKey)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	evidence := filepath.Join(t.TempDir(), "evidence.json")
	if err := os.WriteFile(evidence, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	digest, err := LoadEvidence(evidence, repo.ProviderID(), target)
	if err != nil || len(digest) != 64 {
		t.Fatalf("digest=%q err=%v", digest, err)
	}
	providerDigest, err := LoadProviderEvidence(evidence, repo.ProviderID(), target.Epoch)
	if err != nil || providerDigest != digest {
		t.Fatalf("provider digest=%q err=%v", providerDigest, err)
	}
	if _, err := LoadProviderEvidence(evidence, repo.ProviderID(), target.Epoch+"-drift"); err == nil {
		t.Fatal("provider evidence was accepted for a different epoch")
	}
	operationalTarget, err := repo.EnsureMailbox(context.Background(), did, "default")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEvidence(evidence, repo.ProviderID(), operationalTarget); err != nil {
		t.Fatalf("disposable-space evidence did not certify the same provider epoch: %v", err)
	}
	if _, err := LoadEvidence(evidence, repo.ProviderID()+"-other", target); err == nil {
		t.Fatal("evidence was accepted for a different provider")
	}
	if err := os.Chmod(evidence, 0o440); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", filepath.Dir(evidence))
	if _, err := LoadEvidence(evidence, repo.ProviderID(), target); err != nil {
		t.Fatalf("systemd credential evidence was rejected: %v", err)
	}
	if err := os.Chmod(evidence, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEvidence(evidence, repo.ProviderID(), target); err == nil || !strings.Contains(err.Error(), "owner-only") {
		t.Fatalf("broad evidence err=%v", err)
	}
}
