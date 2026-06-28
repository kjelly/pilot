package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestListRuns(t *testing.T) {
	tmp := t.TempDir()
	st, err := Open(filepath.Join(tmp, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	now := time.Now()
	for i, name := range []string{"a.yml", "b.yml", "c.yml"} {
		if err := st.CreateRun(&Run{
			ID:        "run" + string(rune('a'+i)),
			StartedAt: now.Add(time.Duration(i) * time.Second),
			Mode:      "test",
			Playbook:  name,
			Model:     "test",
			Status:    "running",
		}); err != nil {
			t.Fatal(err)
		}
	}

	runs, err := st.ListRuns("", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 3 {
		t.Fatalf("got %d runs, want 3", len(runs))
	}
	// Newest first.
	if runs[0].Playbook != "c.yml" || runs[2].Playbook != "a.yml" {
		t.Errorf("ordering wrong: %+v", runs)
	}

	// Limit.
	runs, err = st.ListRuns("", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 {
		t.Errorf("limit not respected: got %d", len(runs))
	}
}

func TestListRunsByBatch(t *testing.T) {
	tmp := t.TempDir()
	st, err := Open(filepath.Join(tmp, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	now := time.Now()
	for i, name := range []string{"a.yml", "b.yml", "c.yml"} {
		batch := ""
		if i < 2 {
			batch = "batch1"
		}
		if err := st.CreateRun(&Run{
			ID:        "run" + string(rune('a'+i)),
			StartedAt: now.Add(time.Duration(i) * time.Second),
			Mode:      "test",
			Playbook:  name,
			BatchID:   batch,
			Model:     "test",
			Status:    "running",
		}); err != nil {
			t.Fatal(err)
		}
	}

	runs, err := st.ListRuns("batch1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 {
		t.Errorf("batch filter wrong: got %d runs", len(runs))
	}
	for _, r := range runs {
		if r.BatchID != "batch1" {
			t.Errorf("non-matching batch leaked: %s", r.BatchID)
		}
	}
}

func TestListRunsEmpty(t *testing.T) {
	tmp := t.TempDir()
	st, err := Open(filepath.Join(tmp, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	runs, err := st.ListRuns("", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 0 {
		t.Errorf("empty DB should return 0, got %d", len(runs))
	}
}
