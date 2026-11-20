package db

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestProgramPolicyRevocationRoundTrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	programID := "revocation-test-" + time.Now().UTC().Format("20060102150405.000000000")
	digest := strings.Repeat("b", 64)
	t.Cleanup(func() {
		_, _ = d.Exec("DELETE FROM program_policy_revocations WHERE program_id=$1 AND source_sha256=$2", programID, digest)
	})
	ctx := context.Background()
	if err := d.RevokeProgramPolicy(ctx, programID, digest, "operator-1", "program policy changed"); err != nil {
		t.Fatal(err)
	}
	record, err := d.GetProgramPolicyRevocation(ctx, programID, digest)
	if err != nil || record == nil {
		t.Fatalf("get revocation: record=%+v err=%v", record, err)
	}
	if record.ProgramID != programID || record.SourceSHA256 != digest ||
		record.RevokedBy != "operator-1" || record.Reason != "program policy changed" || record.RevokedAt.IsZero() {
		t.Fatalf("unexpected revocation record: %+v", record)
	}
	// A later request is idempotent and cannot rewrite the original operator
	// attestation or reason.
	if err := d.RevokeProgramPolicy(ctx, programID, digest, "operator-2", "different reason"); err != nil {
		t.Fatal(err)
	}
	record, err = d.GetProgramPolicyRevocation(ctx, programID, digest)
	if err != nil || record == nil || record.RevokedBy != "operator-1" || record.Reason != "program policy changed" {
		t.Fatalf("first revocation attestation was overwritten: record=%+v err=%v", record, err)
	}
	revoked, err := d.IsProgramPolicyRevoked(ctx, programID, digest)
	if err != nil || !revoked {
		t.Fatalf("expected revoked=true, got %v err=%v", revoked, err)
	}
	active, err := d.IsProgramPolicyRevoked(ctx, programID, strings.Repeat("c", 64))
	if err != nil || active {
		t.Fatalf("new source digest should remain active, got %v err=%v", active, err)
	}
}

func TestProgramPolicyRevocationValidatesIdentityAndAttestation(t *testing.T) {
	d := &DB{}
	ctx := context.Background()
	cases := []struct {
		programID, digest, actor, reason string
	}{
		{"", strings.Repeat("a", 64), "operator", "reason"},
		{"program", "bad", "operator", "reason"},
		{"program", strings.Repeat("a", 64), "", "reason"},
		{"program", strings.Repeat("a", 64), "operator", ""},
		{"program", strings.Repeat("a", 64), "operator", strings.Repeat("x", 2049)},
	}
	for i, tc := range cases {
		if err := d.RevokeProgramPolicy(ctx, tc.programID, tc.digest, tc.actor, tc.reason); err == nil {
			t.Errorf("case %d: invalid revocation accepted", i)
		}
	}
}
