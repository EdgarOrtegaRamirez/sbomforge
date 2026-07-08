# SBOMForge

SBOMForge is a Software Bill of Materials (SBOM) generation, parsing, and comparison toolkit in Go. Supports SPDX 2.3 and CycloneDX 1.5.

## Code Structure

- `cmd/sbomforge/main.go` — CLI entry point
- `internal/sbom/` — Core SBOM model, SPDX 2.3, utilities
- `internal/parsers/` — SPDX 2.3 and CycloneDX 1.5 parsers
- `internal/compare/` — SBOM diff, merge, comparison

## Build & Test

```bash
go build ./...
go vet ./...
go test ./...
golangci-lint run
```

## Adding Features

1. Add to `internal/` for new logic, add tests alongside source
2. Add CLI command in `cmd/sbomforge/main.go` with matching tests
3. Update README.md
4. Update AGENTS.md if architecture changes
