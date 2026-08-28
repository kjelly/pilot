package detection

// FusedResult is a candidate's post-fusion score (spec §19). Source is
// "local" or "model", naming which category/contributors won.
type FusedResult struct {
	Score        float64
	Category     string
	Contributors []Contributor
	Source       string
}

// categoryEscalationMargin is spec §19's "effective_model_score >=
// local_score + 0.05" threshold for the model to also win category/contributors.
const categoryEscalationMargin = 0.05

// FuseLocalOnly is the fused result when the provider is disabled,
// unavailable, or its result was discarded for this candidate — spec §19:
// "fused_score = local_score".
func FuseLocalOnly(local LocalScoreResult) FusedResult {
	return FusedResult{Score: local.Score, Category: local.Category, Contributors: local.Contributors, Source: "local"}
}

// modelContributorsToContributors adapts the wire ModelContributor shape
// (feature/score only) to the internal Contributor shape used everywhere
// else (baseline/cohort's Category field has no model equivalent — spec
// §19 doesn't define a per-contributor category for model output, so it's
// left empty).
func modelContributorsToContributors(cs []ModelContributor) []Contributor {
	out := make([]Contributor, 0, len(cs))
	for _, c := range cs {
		out = append(out, Contributor{Feature: c.Feature, Score: c.Score})
	}
	return out
}

// FuseCandidate implements spec §19 exactly for a candidate whose model
// response has status=ok: model can only escalate, never suppress, local
// detection. category/contributors switch to the model's only when the
// model's effective score clears local_score by categoryEscalationMargin.
func FuseCandidate(local LocalScoreResult, model ModelCandidateResponse) FusedResult {
	effectiveModelScore := model.Score * model.Confidence
	fusedScore := local.Score
	if effectiveModelScore > fusedScore {
		fusedScore = effectiveModelScore
	}
	if effectiveModelScore >= local.Score+categoryEscalationMargin {
		return FusedResult{
			Score:        fusedScore,
			Category:     model.CategoryHint,
			Contributors: modelContributorsToContributors(model.Contributors),
			Source:       "model",
		}
	}
	return FusedResult{Score: fusedScore, Category: local.Category, Contributors: local.Contributors, Source: "local"}
}

// FuseInsufficientData implements spec §19's status=insufficient_data
// rule: ignore the model entirely, fused_score=local_score.
func FuseInsufficientData(local LocalScoreResult) FusedResult {
	return FuseLocalOnly(local)
}
