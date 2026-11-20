package db

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// ProgramPolicyRevocation is an irreversible marker for one exact program
// policy source. A refreshed source has a different digest and requires a new
// explicit approval before it can be used.
type ProgramPolicyRevocation struct {
	ProgramID   string    `json:"program_id"`
	SourceSHA256 string   `json:"source_sha256"`
	RevokedAt   time.Time `json:"revoked_at"`
	RevokedBy   string    `json:"revoked_by"`
	Reason      string    `json:"reason"`
}

func validateProgramPolicyIdentity(programID, digest string) error {
	programID = strings.TrimSpace(programID)
	decoded, err := hex.DecodeString(strings.TrimSpace(digest))
	if programID == "" || err != nil || len(decoded) != 32 {
		return errors.New("ProgramPolicy revocation requires a program id and SHA-256 source digest")
	}
	return nil
}

// RevokeProgramPolicy permanently revokes one exact source snapshot. Repeated
// calls are idempotent; the first operator attestation remains authoritative.
func (d *DB) RevokeProgramPolicy(ctx context.Context, programID, digest, actor, reason string) error {
	programID, digest, actor, reason = strings.TrimSpace(programID), strings.ToLower(strings.TrimSpace(digest)), strings.TrimSpace(actor), strings.TrimSpace(reason)
	if err := validateProgramPolicyIdentity(programID, digest); err != nil {
		return err
	}
	if actor == "" || reason == "" || len(actor) > 256 || len(reason) > 2048 {
		return errors.New("ProgramPolicy revocation requires a valid actor and a reason of at most 2048 characters")
	}
	_, err := d.ExecContext(ctx, `
INSERT INTO program_policy_revocations(program_id, source_sha256, revoked_by, reason)
VALUES ($1,$2,$3,$4)
ON CONFLICT (program_id, source_sha256) DO NOTHING`, programID, digest, actor, reason)
	return err
}

// GetProgramPolicyRevocation returns the revocation marker for an exact source,
// or nil if it remains active.
func (d *DB) GetProgramPolicyRevocation(ctx context.Context, programID, digest string) (*ProgramPolicyRevocation, error) {
	programID, digest = strings.TrimSpace(programID), strings.ToLower(strings.TrimSpace(digest))
	if err := validateProgramPolicyIdentity(programID, digest); err != nil {
		return nil, err
	}
	var out ProgramPolicyRevocation
	err := d.QueryRowContext(ctx, `
SELECT program_id, source_sha256, revoked_at, revoked_by, reason
FROM program_policy_revocations WHERE program_id=$1 AND source_sha256=$2`, programID, digest).
		Scan(&out.ProgramID, &out.SourceSHA256, &out.RevokedAt, &out.RevokedBy, &out.Reason)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// IsProgramPolicyRevoked fails closed on database errors: callers must not
// interpret an unavailable revocation store as an active policy.
func (d *DB) IsProgramPolicyRevoked(ctx context.Context, programID, digest string) (bool, error) {
	record, err := d.GetProgramPolicyRevocation(ctx, programID, digest)
	return record != nil, err
}
