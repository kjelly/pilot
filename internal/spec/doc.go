// Package spec parses, validates, and compiles pilot verification
// specs (the markdown checklist format used by `pilot spec <file.md>`).
//
// A spec is a structured document with three concerns:
//
//  1. Metadata (target system, scope, alignment) — informational.
//  2. Checklist rows (| ID | Category | Check | Expected | Command |) —
//     one row per requirement. Each row MUST have an ID, an Expected
//     value that is machine-comparable, and a Command that can run
//     in one shell line.
//  3. Optional playbook alignment section — for documentation only.
//
// spec.Parser converts a markdown file into a Spec value. spec.Lint
// checks that every row satisfies the contract above. spec.Generator
// walks the checklist and produces one Ansible task per row, then
// dedupes by (ModuleName, Parameters hash) so a spec that lists
// "disable root SSH" twice yields one task.
//
// Traceability: spec.Checkpoint records the (spec_id, task_index)
// mapping so an auditor can answer "where in the playbook does
// requirement C2.5.1 live?". The Pilot store links each generated
// proposal back to its Checkpoint via Proposal.SpecID + Proposal.RowIndex.
package spec
