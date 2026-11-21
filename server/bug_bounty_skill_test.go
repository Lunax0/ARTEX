package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/skill"
)

func TestBugBountyHuntingSkillIsDiscoverableAndPolicyBound(t *testing.T) {
	dir := filepath.Join("..", "skills")
	reg, err := skill.LoadDir(dir)
	if err != nil {
		t.Fatalf("load shipped skills: %v", err)
	}
	loaded, ok := reg.Get("bug-bounty-hunting")
	if !ok {
		t.Fatal("bug-bounty-hunting skill is not discoverable by the shipped skill registry")
	}
	if loaded.Description == "" {
		t.Fatal("bug-bounty-hunting description is empty")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "bug-bounty-hunting", "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	flat := strings.ToLower(strings.Join(strings.Fields(body), " "))
	for _, marker := range []string{
		"ProgramPolicy snapshot",
		"do not perform live target requests",
		"researcher-controlled accounts",
		"non-owned personal information",
		"read-only",
		"Phase 0",
		"Phase 10",
		"independent verification",
		"same-program duplicate",
		"human review",
		"confirmed",
		"refuted",
		"blocked",
		"untested",
		"needs_follow_up",
		"ReconFTW",
	} {
		if !strings.Contains(flat, strings.ToLower(marker)) {
			t.Errorf("bug-bounty-hunting skill missing required marker %q", marker)
		}
	}
	if strings.Contains(body, "$YOUR_") || strings.Contains(body, "<YOUR_") {
		t.Fatal("skill contains unresolved private integration placeholders")
	}
}
