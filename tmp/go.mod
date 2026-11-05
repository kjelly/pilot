// tmp/ holds scratch checkouts of other PRs and loose test programs; none of it is
// part of the pilot module. This go.mod makes Go treat tmp/ as a separate module, so
// `go test ./...`, `go vet ./...` and golangci-lint run from the repository root never
// compile what is under it (AGENTS.md §5). A scratch program that imports pilot
// packages belongs in a full copy of the repository under tmp/<name>/, not loose here.
module github.com/kjelly/pilot/tmp

go 1.26
