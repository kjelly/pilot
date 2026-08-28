package detection

import "testing"

// TestProvider_CandidateLimitDropsLowestScoresDeterministically (spec
// §35/§48): sorted local_score DESC / pilot_host ASC, capped at
// MaxCandidatesPerCycle — the dropped tail is always the lowest scores,
// tie-broken by host name, never arbitrary map iteration order.
func TestProvider_CandidateLimitDropsLowestScoresDeterministically(t *testing.T) {
	var all []Candidate
	// 20 candidates, scores descending except two ties at the cutoff to
	// also exercise the host-ASC tiebreak.
	for i := 0; i < 20; i++ {
		score := 1.0 - float64(i)*0.01
		host := string(rune('a' + i))
		all = append(all, Candidate{Host: host, LocalScore: LocalScoreResult{Valid: true, Score: score}})
	}
	// Force a tie between the 16th and 17th by score so the ASC-host
	// tiebreak is exercised right at the cutoff boundary.
	all[15].LocalScore.Score = 0.5
	all[16].LocalScore.Score = 0.5

	kept, dropped := SelectCandidates(all)
	if len(kept) != MaxCandidatesPerCycle {
		t.Fatalf("kept = %d, want %d", len(kept), MaxCandidatesPerCycle)
	}
	if len(dropped) != len(all)-MaxCandidatesPerCycle {
		t.Fatalf("dropped = %d, want %d", len(dropped), len(all)-MaxCandidatesPerCycle)
	}
	for i := 1; i < len(kept); i++ {
		prev, cur := kept[i-1], kept[i]
		if prev.LocalScore.Score < cur.LocalScore.Score {
			t.Fatalf("kept not sorted DESC by score at %d: %v then %v", i, prev, cur)
		}
		if prev.LocalScore.Score == cur.LocalScore.Score && prev.Host > cur.Host {
			t.Fatalf("tie at %d not broken host ASC: %q then %q", i, prev.Host, cur.Host)
		}
	}
	for _, d := range dropped {
		for _, k := range kept {
			if d.LocalScore.Score > k.LocalScore.Score {
				t.Fatalf("dropped candidate %v scores higher than kept candidate %v", d, k)
			}
		}
	}

	// Re-running SelectCandidates on the same input must be deterministic.
	kept2, dropped2 := SelectCandidates(all)
	for i := range kept {
		if kept[i].Host != kept2[i].Host {
			t.Fatalf("non-deterministic kept order at %d: %q vs %q", i, kept[i].Host, kept2[i].Host)
		}
	}
	for i := range dropped {
		if dropped[i].Host != dropped2[i].Host {
			t.Fatalf("non-deterministic dropped order at %d: %q vs %q", i, dropped[i].Host, dropped2[i].Host)
		}
	}
}

func TestChunkBatches_GroupsOfFour(t *testing.T) {
	var candidates []Candidate
	for i := 0; i < MaxCandidatesPerCycle; i++ {
		candidates = append(candidates, Candidate{Host: string(rune('a' + i))})
	}
	batches := ChunkBatches(candidates)
	if len(batches) != MaxBatchesPerCycle {
		t.Fatalf("batches = %d, want %d", len(batches), MaxBatchesPerCycle)
	}
	for _, b := range batches {
		if len(b) != ModelBatchSize {
			t.Errorf("batch size = %d, want %d", len(b), ModelBatchSize)
		}
	}
}
