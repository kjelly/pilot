package detection

import (
	"testing"
	"time"
)

func TestStore_SaveBaselineSamples_RoundTripsThroughLoadBaselineHistory(t *testing.T) {
	s := openTestStore(t)
	evaluationTime := int64(1_700_000_000)
	bucket := BucketOf(evaluationTime)

	err := s.SaveBaselineSamples([]BaselineSampleRecord{
		{SubjectID: "web-1", SubjectKind: SubjectKindManagedHost, Feature: "cpu_utilization", BucketTS: bucket, Value: 0.42},
		{SubjectID: "web-1", SubjectKind: SubjectKindManagedHost, Feature: "memory_used_ratio", BucketTS: bucket, Value: 0.7},
		{SubjectID: "web-2", SubjectKind: SubjectKindManagedHost, Feature: "cpu_utilization", BucketTS: bucket, Value: 0.1},
	}, evaluationTime)
	if err != nil {
		t.Fatalf("SaveBaselineSamples: %v", err)
	}

	warm, err := s.LoadBaselineHistory(time.Unix(evaluationTime, 0), SubjectKindManagedHost)
	if err != nil {
		t.Fatalf("LoadBaselineHistory: %v", err)
	}
	got := warm.History("web-1", "cpu_utilization")
	if len(got) != 1 || got[0] != 0.42 {
		t.Fatalf("web-1/cpu_utilization history = %v, want [0.42]", got)
	}
	got = warm.History("web-1", "memory_used_ratio")
	if len(got) != 1 || got[0] != 0.7 {
		t.Fatalf("web-1/memory_used_ratio history = %v, want [0.7]", got)
	}
	got = warm.History("web-2", "cpu_utilization")
	if len(got) != 1 || got[0] != 0.1 {
		t.Fatalf("web-2/cpu_utilization history = %v, want [0.1]", got)
	}
}

func TestStore_SaveBaselineSamples_UpsertOverwritesSameBucket(t *testing.T) {
	s := openTestStore(t)
	evaluationTime := int64(1_700_000_000)
	bucket := BucketOf(evaluationTime)

	if err := s.SaveBaselineSamples([]BaselineSampleRecord{
		{SubjectID: "web-1", SubjectKind: SubjectKindManagedHost, Feature: "cpu_utilization", BucketTS: bucket, Value: 0.1},
	}, evaluationTime); err != nil {
		t.Fatalf("first save: %v", err)
	}
	if err := s.SaveBaselineSamples([]BaselineSampleRecord{
		{SubjectID: "web-1", SubjectKind: SubjectKindManagedHost, Feature: "cpu_utilization", BucketTS: bucket, Value: 0.9},
	}, evaluationTime); err != nil {
		t.Fatalf("second save: %v", err)
	}

	warm, err := s.LoadBaselineHistory(time.Unix(evaluationTime, 0), SubjectKindManagedHost)
	if err != nil {
		t.Fatalf("LoadBaselineHistory: %v", err)
	}
	got := warm.History("web-1", "cpu_utilization")
	if len(got) != 1 || got[0] != 0.9 {
		t.Fatalf("history = %v, want [0.9] (later write must overwrite the same bucket)", got)
	}
}

func TestStore_SaveBaselineSamples_PrunesBucketsOlderThan24h(t *testing.T) {
	s := openTestStore(t)
	oldTime := int64(1_700_000_000)
	oldBucket := BucketOf(oldTime)

	if err := s.SaveBaselineSamples([]BaselineSampleRecord{
		{SubjectID: "web-1", SubjectKind: SubjectKindManagedHost, Feature: "cpu_utilization", BucketTS: oldBucket, Value: 0.5},
	}, oldTime); err != nil {
		t.Fatalf("save old sample: %v", err)
	}

	// A later cycle for the SAME (host, feature), 25h after the old
	// sample, must prune it — mirroring HostBaselineStore.Evict's 24h
	// horizon (spec §14.2).
	laterTime := oldTime + 25*60*60
	laterBucket := BucketOf(laterTime)
	if err := s.SaveBaselineSamples([]BaselineSampleRecord{
		{SubjectID: "web-1", SubjectKind: SubjectKindManagedHost, Feature: "cpu_utilization", BucketTS: laterBucket, Value: 0.6},
	}, laterTime); err != nil {
		t.Fatalf("save later sample: %v", err)
	}

	warm, err := s.LoadBaselineHistory(time.Unix(laterTime, 0), SubjectKindManagedHost)
	if err != nil {
		t.Fatalf("LoadBaselineHistory: %v", err)
	}
	got := warm.History("web-1", "cpu_utilization")
	if len(got) != 1 || got[0] != 0.6 {
		t.Fatalf("history = %v, want only the later [0.6] sample (old one should be pruned)", got)
	}
}

func TestStore_LoadBaselineHistory_EmptyTableYieldsEmptyStore(t *testing.T) {
	s := openTestStore(t)
	warm, err := s.LoadBaselineHistory(time.Unix(1_700_000_000, 0), SubjectKindManagedHost)
	if err != nil {
		t.Fatalf("LoadBaselineHistory: %v", err)
	}
	if got := warm.History("web-1", "cpu_utilization"); len(got) != 0 {
		t.Fatalf("history = %v, want empty on a fresh install", got)
	}
}

func TestStore_SaveBaselineSamples_EmptyBatchIsANoop(t *testing.T) {
	s := openTestStore(t)
	if err := s.SaveBaselineSamples(nil, 1_700_000_000); err != nil {
		t.Fatalf("SaveBaselineSamples(nil): %v", err)
	}
}

func TestStore_LoadBaselineHistory_FrozenWindowOnlyForActiveSubjectKind(t *testing.T) {
	for _, state := range []string{"normal", "firing", "recovering", "resolved", "other-kind"} {
		t.Run(state, func(t *testing.T) {
			s := openTestStore(t)
			lastNormal := BucketOf(1_700_000_000)
			now := lastNormal + 10*24*60*60
			if state != "normal" {
				kind, episodeState := SubjectKindManagedHost, state
				if state == "other-kind" {
					kind, episodeState = "network_device", "firing"
				}
				if err := s.ApplyTransition(EpisodeRecord{
					SignalID: "sig-1", Fingerprint: "fp-1", SubjectID: "web-1", SubjectKind: kind,
					ProfileID: "test-v1", ProfileVersion: 1, State: episodeState, Severity: "warning",
					CreatedAt: time.Unix(lastNormal, 0), UpdatedAt: time.Unix(lastNormal, 0), Revision: 1,
				}, HistoryRecord{SignalID: "sig-1", Revision: 1, EventType: "create", PayloadJSON: "{}", CreatedAt: time.Unix(lastNormal, 0)}, nil); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.SaveBaselineSamples([]BaselineSampleRecord{
				{SubjectID: "web-1", SubjectKind: SubjectKindManagedHost, Feature: "cpu_utilization", BucketTS: lastNormal - 25*60*60, Value: 0.1},
				{SubjectID: "web-1", SubjectKind: SubjectKindManagedHost, Feature: "cpu_utilization", BucketTS: lastNormal - 60*60, Value: 0.2},
				{SubjectID: "web-1", SubjectKind: SubjectKindManagedHost, Feature: "cpu_utilization", BucketTS: lastNormal, Value: 0.3},
				{SubjectID: "web-1", SubjectKind: SubjectKindManagedHost, Feature: "cpu_utilization", BucketTS: now + 60, Value: 0.9},
			}, lastNormal-25*60*60); err != nil {
				t.Fatal(err)
			}
			warm, err := s.LoadBaselineHistory(time.Unix(now, 0), SubjectKindManagedHost)
			if err != nil {
				t.Fatal(err)
			}
			got := warm.History("web-1", "cpu_utilization")
			if state == "firing" || state == "recovering" {
				if len(got) != 2 {
					t.Fatalf("frozen baseline = %v, want the two samples in the last normal 24h window", got)
				}
				for _, value := range got {
					if value != 0.2 && value != 0.3 {
						t.Fatalf("out-of-window or future sample restored: %v", got)
					}
				}
			} else if len(got) != 0 {
				t.Fatalf("inactive or different-kind subject loaded stale samples: %v", got)
			}
		})
	}
}
