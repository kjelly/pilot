package detection

import "testing"

// TestFusion_ModelCanEscalateButNeverSuppress (spec §19/§48): the model can
// raise the fused score above local, but a low/negative model contribution
// can never pull it below local_score.
func TestFusion_ModelCanEscalateButNeverSuppress(t *testing.T) {
	local := LocalScoreResult{Valid: true, Score: 0.7, Category: "local-cat", Contributors: []Contributor{{Feature: "cpu", Score: 0.7}}}

	// Escalates: effective_model_score (0.9*0.9=0.81) > local (0.7), and
	// clears the +0.05 category-switch margin.
	high := ModelCandidateResponse{CandidateID: "host-a", Score: 0.9, Confidence: 0.9, CategoryHint: "model-cat", Contributors: []ModelContributor{{Feature: "cpu", Score: 0.9}}}
	fr := FuseCandidate(local, high)
	if fr.Score <= local.Score {
		t.Fatalf("expected escalation above local.Score=%v, got %v", local.Score, fr.Score)
	}
	if fr.Category != "model-cat" || fr.Source != "model" {
		t.Errorf("expected model category/source to win, got category=%q source=%q", fr.Category, fr.Source)
	}

	// Never suppresses: a low-confidence/low-score model result must not
	// pull the fused score below local_score.
	low := ModelCandidateResponse{CandidateID: "host-a", Score: 0.1, Confidence: 0.1, CategoryHint: "model-cat", Contributors: nil}
	fr2 := FuseCandidate(local, low)
	if fr2.Score != local.Score {
		t.Errorf("expected fused score to floor at local.Score=%v, got %v", local.Score, fr2.Score)
	}
	if fr2.Category != local.Category || fr2.Source != "local" {
		t.Errorf("expected local category/source to win when model doesn't clear the margin, got category=%q source=%q", fr2.Category, fr2.Source)
	}
}

// TestFusion_InsufficientDataUsesLocalScore (spec §19/§48).
func TestFusion_InsufficientDataUsesLocalScore(t *testing.T) {
	local := LocalScoreResult{Valid: true, Score: 0.8, Category: "local-cat", Contributors: []Contributor{{Feature: "mem", Score: 0.8}}}
	fr := FuseInsufficientData(local)
	if fr.Score != local.Score || fr.Category != local.Category || fr.Source != "local" {
		t.Errorf("expected insufficient_data to be pure local passthrough, got %+v", fr)
	}
}

func TestFuseLocalOnly_MatchesLocalExactly(t *testing.T) {
	local := LocalScoreResult{Valid: true, Score: 0.42, Category: "c", Contributors: []Contributor{{Feature: "f", Score: 0.42}}}
	fr := FuseLocalOnly(local)
	if fr.Score != local.Score || fr.Category != local.Category || fr.Source != "local" {
		t.Errorf("FuseLocalOnly diverged from local: %+v vs %+v", fr, local)
	}
}

func TestFuseCandidate_ExactlyAtMarginUsesModel(t *testing.T) {
	local := LocalScoreResult{Valid: true, Score: 0.5, Category: "local-cat"}
	// effective_model_score = 1.0 * 0.55 = 0.55 == local.Score + 0.05 exactly.
	model := ModelCandidateResponse{CandidateID: "x", Score: 1.0, Confidence: 0.55, CategoryHint: "model-cat"}
	fr := FuseCandidate(local, model)
	if fr.Source != "model" {
		t.Errorf("expected the exact +0.05 margin to count as clearing it (>=), got source=%q", fr.Source)
	}
}
