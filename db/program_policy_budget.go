package db

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/Autumn-27/artex/policy"
)

const policyBudgetLeaseGrace = 30 * time.Second

func validateProgramPolicyBudget(key string, limits policy.Limits) error {
	if key == "" || math.IsNaN(limits.RequestsPerSecond) ||
		math.IsInf(limits.RequestsPerSecond, 0) || limits.RequestsPerSecond <= 0 ||
		limits.RequestsPerSecond > 1000 || limits.Burst < 1 || limits.Burst > 1000 ||
		limits.MaxConcurrency < 1 || limits.MaxConcurrency > 128 ||
		limits.RequestTimeoutSecond < 1 || limits.RequestTimeoutSecond > 600 {
		return errors.New("invalid ProgramPolicy shared budget identity or limits")
	}
	return nil
}

func sleepPolicyBudget(ctx context.Context, delay time.Duration) error {
	if delay < 10*time.Millisecond {
		delay = 10 * time.Millisecond
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// AcquireProgramPolicyBudget atomically charges one request token and acquires
// a concurrency lease shared by every ARTEX process using this PostgreSQL DB.
// The returned release function is safe to call more than once.
func (d *DB) AcquireProgramPolicyBudget(ctx context.Context, key string, limits policy.Limits) (func(), error) {
	if err := validateProgramPolicyBudget(key, limits); err != nil {
		return nil, err
	}
	leaseTTL := time.Duration(limits.RequestTimeoutSecond)*time.Second + policyBudgetLeaseGrace
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		tx, err := d.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		_, err = tx.ExecContext(ctx, `
INSERT INTO program_policy_budget_state
    (budget_key, requests_per_second, burst, max_concurrency, tokens, refilled_at, updated_at)
VALUES ($1,$2,$3,$4,$3,now(),now())
ON CONFLICT (budget_key) DO NOTHING`, key, limits.RequestsPerSecond, limits.Burst, limits.MaxConcurrency)
		if err != nil {
			_ = tx.Rollback()
			return nil, err
		}
		var rps, tokens float64
		var burst, maxConcurrency int
		var refilledAt time.Time
		err = tx.QueryRowContext(ctx, `
SELECT requests_per_second, burst, max_concurrency, tokens, refilled_at
FROM program_policy_budget_state WHERE budget_key=$1 FOR UPDATE`, key).
			Scan(&rps, &burst, &maxConcurrency, &tokens, &refilledAt)
		if err != nil {
			_ = tx.Rollback()
			return nil, err
		}
		if rps != limits.RequestsPerSecond || burst != limits.Burst || maxConcurrency != limits.MaxConcurrency {
			_ = tx.Rollback()
			return nil, errors.New("ProgramPolicy shared budget key was reused with different limits")
		}
		var now time.Time
		if err := tx.QueryRowContext(ctx, "SELECT now()").Scan(&now); err != nil {
			_ = tx.Rollback()
			return nil, err
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM program_policy_budget_leases WHERE budget_key=$1 AND expires_at <= $2", key, now)
		if err != nil {
			_ = tx.Rollback()
			return nil, err
		}
		elapsed := now.Sub(refilledAt).Seconds()
		if elapsed < 0 {
			elapsed = 0
		}
		tokens = math.Min(float64(burst), tokens+elapsed*rps)
		var active int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM program_policy_budget_leases WHERE budget_key=$1", key).Scan(&active); err != nil {
			_ = tx.Rollback()
			return nil, err
		}
		if tokens >= 1 && active < maxConcurrency {
			var leaseID int64
			_, err = tx.ExecContext(ctx, "UPDATE program_policy_budget_state SET tokens=$2, refilled_at=$3, updated_at=$3 WHERE budget_key=$1", key, tokens-1, now)
			if err == nil {
				err = tx.QueryRowContext(ctx, "INSERT INTO program_policy_budget_leases(budget_key, expires_at) VALUES ($1,$2) RETURNING id", key, now.Add(leaseTTL)).Scan(&leaseID)
			}
			if err != nil {
				_ = tx.Rollback()
				return nil, err
			}
			if err := tx.Commit(); err != nil {
				return nil, err
			}
			var once sync.Once
			return func() {
				once.Do(func() {
					releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					_, _ = d.ExecContext(releaseCtx, "DELETE FROM program_policy_budget_leases WHERE id=$1", leaseID)
				})
			}, nil
		}
		wait := 100 * time.Millisecond
		if tokens < 1 {
			wait = time.Duration((1 - tokens) / rps * float64(time.Second))
		}
		_, err = tx.ExecContext(ctx, "UPDATE program_policy_budget_state SET tokens=$2, refilled_at=$3, updated_at=$3 WHERE budget_key=$1", key, tokens, now)
		if err != nil {
			_ = tx.Rollback()
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		if err := sleepPolicyBudget(ctx, wait); err != nil {
			return nil, err
		}
	}
}

// ConsumeProgramPolicyRequest charges an additional request (for example a
// redirect hop) against the shared token bucket without taking another lease.
func (d *DB) ConsumeProgramPolicyRequest(ctx context.Context, key string, limits policy.Limits) error {
	if err := validateProgramPolicyBudget(key, limits); err != nil {
		return err
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		tx, err := d.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		var rps, tokens float64
		var burst int
		var refilledAt time.Time
		err = tx.QueryRowContext(ctx, `
SELECT requests_per_second, burst, tokens, refilled_at
FROM program_policy_budget_state WHERE budget_key=$1 FOR UPDATE`, key).
			Scan(&rps, &burst, &tokens, &refilledAt)
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("ProgramPolicy budget state unavailable: %w", err)
		}
		if rps != limits.RequestsPerSecond || burst != limits.Burst {
			_ = tx.Rollback()
			return errors.New("ProgramPolicy shared budget key was reused with different limits")
		}
		var now time.Time
		if err := tx.QueryRowContext(ctx, "SELECT now()").Scan(&now); err != nil {
			_ = tx.Rollback()
			return err
		}
		elapsed := now.Sub(refilledAt).Seconds()
		if elapsed < 0 {
			elapsed = 0
		}
		tokens = math.Min(float64(burst), tokens+elapsed*rps)
		if tokens >= 1 {
			_, err = tx.ExecContext(ctx, "UPDATE program_policy_budget_state SET tokens=$2, refilled_at=$3, updated_at=$3 WHERE budget_key=$1", key, tokens-1, now)
			if err != nil {
				_ = tx.Rollback()
				return err
			}
			return tx.Commit()
		}
		wait := time.Duration((1-tokens)/rps*float64(time.Second))
		_, err = tx.ExecContext(ctx, "UPDATE program_policy_budget_state SET tokens=$2, refilled_at=$3, updated_at=$3 WHERE budget_key=$1", key, tokens, now)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		if err := sleepPolicyBudget(ctx, wait); err != nil {
			return err
		}
	}
}
