package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Autumn-27/artex/policy"
)

func openBudgetTestDB(t *testing.T) *DB {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func TestProgramPolicyBudgetIsSharedAcrossDBHandles(t *testing.T) {
	d1 := openBudgetTestDB(t)
	d2 := openBudgetTestDB(t)
	key := fmt.Sprintf("shared-budget-test-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = d1.Exec("DELETE FROM program_policy_budget_state WHERE budget_key=$1", key)
	})
	limits := policy.Limits{
		RequestsPerSecond: 100, Burst: 10, MaxConcurrency: 1,
		RequestTimeoutSecond: 3, MaxRetries: 0,
	}
	releaseFirst, err := d1.AcquireProgramPolicyBudget(context.Background(), key, limits)
	if err != nil {
		t.Fatal(err)
	}
	acquired := make(chan func(), 1)
	failed := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		release, err := d2.AcquireProgramPolicyBudget(ctx, key, limits)
		if err != nil {
			failed <- err
			return
		}
		acquired <- release
	}()
	select {
	case release := <-acquired:
		release()
		releaseFirst()
		t.Fatal("second DB handle acquired a concurrent slot before the first lease was released")
	case err := <-failed:
		releaseFirst()
		t.Fatalf("second DB handle failed before first lease release: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	releaseFirst()
	select {
	case release := <-acquired:
		release()
	case err := <-failed:
		t.Fatalf("second DB handle did not acquire after release: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("second DB handle remained blocked after first lease release")
	}
}

func TestProgramPolicyBudgetRateIsSharedAcrossDBHandles(t *testing.T) {
	d1 := openBudgetTestDB(t)
	d2 := openBudgetTestDB(t)
	key := fmt.Sprintf("shared-rate-test-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = d1.Exec("DELETE FROM program_policy_budget_state WHERE budget_key=$1", key)
	})
	limits := policy.Limits{
		RequestsPerSecond: 2, Burst: 1, MaxConcurrency: 2,
		RequestTimeoutSecond: 3, MaxRetries: 0,
	}
	release, err := d1.AcquireProgramPolicyBudget(context.Background(), key, limits)
	if err != nil {
		t.Fatal(err)
	}
	release()
	start := time.Now()
	release, err = d2.AcquireProgramPolicyBudget(context.Background(), key, limits)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if elapsed := time.Since(start); elapsed < 350*time.Millisecond {
		t.Fatalf("second DB handle bypassed shared rate limit: waited %s", elapsed)
	}
}

func TestProgramPolicyBudgetHonorsCancellation(t *testing.T) {
	d1 := openBudgetTestDB(t)
	d2 := openBudgetTestDB(t)
	key := fmt.Sprintf("shared-cancel-test-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = d1.Exec("DELETE FROM program_policy_budget_state WHERE budget_key=$1", key)
	})
	limits := policy.Limits{
		RequestsPerSecond: 100, Burst: 10, MaxConcurrency: 1,
		RequestTimeoutSecond: 3, MaxRetries: 0,
	}
	release, err := d1.AcquireProgramPolicyBudget(context.Background(), key, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := d2.AcquireProgramPolicyBudget(ctx, key, limits); err == nil {
		t.Fatal("shared budget acquisition succeeded after context cancellation")
	}
}

func TestProgramPolicyRedirectRequestUsesSharedTokenBucket(t *testing.T) {
	d1 := openBudgetTestDB(t)
	d2 := openBudgetTestDB(t)
	key := fmt.Sprintf("shared-redirect-test-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = d1.Exec("DELETE FROM program_policy_budget_state WHERE budget_key=$1", key)
	})
	limits := policy.Limits{
		RequestsPerSecond: 2, Burst: 1, MaxConcurrency: 1,
		RequestTimeoutSecond: 3, MaxRetries: 0,
	}
	release, err := d1.AcquireProgramPolicyBudget(context.Background(), key, limits)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := d2.ConsumeProgramPolicyRequest(context.Background(), key, limits); err != nil {
		release()
		t.Fatal(err)
	}
	release()
	if elapsed := time.Since(start); elapsed < 350*time.Millisecond {
		t.Fatalf("redirect hop bypassed shared token bucket: waited %s", elapsed)
	}
}
