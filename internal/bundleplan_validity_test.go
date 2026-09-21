package internal

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBundlePlan_RechecksValidityAtWriteTime(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name         string
		afterCheck   bool
		allowExpired bool
		future       bool
	}{
		{"expired while reviewing", false, false, false},
		{"expired after write preflight", true, false, false},
		{"expired explicitly allowed", false, true, false},
		{"clock moves before not before", false, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newBundlePlanFixture(t)
			fixture.input.Formats = []string{"pem"}
			fixture.input.AllowExpired = test.allowExpired
			initial, err := PlanBundleExports(context.Background(), fixture.input)
			if err != nil {
				t.Fatal(err)
			}
			if err := initial.Write(context.Background()); err != nil {
				t.Fatal(err)
			}
			manifest := filepath.Join(initial.Entries[0].OutputDirectory, "manifest.json")
			original := mustReadTestFile(t, manifest)
			plan, err := PlanBundleExports(context.Background(), fixture.input)
			if err != nil {
				t.Fatal(err)
			}
			writeTime := fixture.leaf.cert.NotAfter.Add(time.Second)
			if test.future {
				writeTime = fixture.leaf.cert.NotBefore.Add(-time.Second)
			}
			calls := 0
			plan.now = func() time.Time {
				calls++
				if test.afterCheck && calls == 1 {
					return time.Now()
				}
				return writeTime
			}
			err = plan.Write(context.Background())
			if test.allowExpired && !test.future {
				if err != nil || plan.Entries[0].Status != "replaced" {
					t.Fatalf("explicitly allowed expired candidate failed: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrBundlePlanBlocked) || plan.Entries[0].Status != "blocked" {
				t.Fatalf("stale validity did not block writing: %v", err)
			}
			if test.future && !strings.Contains(plan.Entries[0].Reason, "not yet valid") {
				t.Fatalf("unexpected future-certificate decision: %s", plan.Entries[0].Reason)
			}
			if string(mustReadTestFile(t, manifest)) != string(original) {
				t.Fatal("invalid-at-write candidate replaced the existing bundle")
			}
		})
	}
}
