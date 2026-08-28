package detection

import _ "embed"

// PromptVersion is spec §36's fixed prompt version. Every batch request
// carries this value, and the audit trail stores it (plus a hash) instead
// of the raw prompt body.
const PromptVersion = 1

// hostAnomalyPromptV1 is the embedded copy of spec §36's prompt contract.
// monitoring/detection/model-prompts/host-anomaly-v1.txt (the repo's
// canonical/operator-facing target path) must stay byte-identical —
// locked by TestModelSchema_EmbeddedCopyMatchesMonitoringTarget.
//
//go:embed prompts/host-anomaly-v1.txt
var hostAnomalyPromptV1 string

// HostAnomalyPrompt returns the versioned system/instructions prompt sent
// to the model provider (spec §36).
func HostAnomalyPrompt() string { return hostAnomalyPromptV1 }

// hostAnomalyFLMPromptV1 is the FLM-protocol system prompt (spec1.md §22):
// a compact pipe-delimited text contract instead of a JSON envelope, since
// FastFlowLM provides no grammar-constrained/structured-output guarantee.
// monitoring/detection/model-prompts/host-anomaly-flm-v1.txt (the repo's
// canonical/operator-facing target path) must stay byte-identical —
// locked by TestModelSchema_EmbeddedCopyMatchesMonitoringTarget.
//
//go:embed prompts/host-anomaly-flm-v1.txt
var hostAnomalyFLMPromptV1 string

// HostAnomalyFLMPrompt returns the FLM-protocol prompt (spec1.md §22).
func HostAnomalyFLMPrompt() string { return hostAnomalyFLMPromptV1 }
