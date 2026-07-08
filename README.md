# SBOMForge

**SBOMForge** — A Software Bill of Materials (SBOM) generation, parsing, and comparison toolkit in Go. Supports SPDX 2.3 and CycloneDX 1.5 formats.

## Features

- **Generate** SBOMs from Go modules, Node.js, Python, and Rust projects
- **Parse** SPDX 2.3 JSON and CycloneDX 1.5 JSON SBOM files
- **Compare** two SBOMs to find added, removed, and changed packages
- **License analysis** — identify copyleft, permissive, and unknown licenses
- **Pure Go** — zero external dependencies

## Install

```bash
go install github.com/EdgarOrtegaRamirez/sbomforge/cmd/sbomforge@latest
```

## Quick Start

### Generate an SBOM from a project directory

```bash
sbomforge generate ./my-project
```

### Parse and display an existing SBOM

```bash
sbomforge parse sbom.json
```

### Compare two SBOMs

```bash
sbomforge compare old.json new.json
```

### Show version

```bash
sbomforge version
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `generate <dir>` | Generate an SBOM from a project directory |
| `parse <file>` | Parse and display an existing SBOM |
| `compare <a> <b>` | Compare two SBOMs |
| `version` | Show version |

## Architecture

```
cmd/sbomforge/       — CLI entry point
internal/sbom/       — SBOM core types, SPDX 2.3 model, utilities
internal/parsers/    — SPDX 2.3 and CycloneDX 1.5 parsers
internal/compare/    — SBOM diff, merge, and comparison logic
```

## Library Usage

```go
import "github.com/EdgarOrtegaRamirez/sbomforge/internal/sbom"

doc := &sbom.SBOM{
    ID:      "SPDXRef-DOCUMENT",
    Name:    "my-project",
    Version: "1.0.0",
    Creator: "sbomforge",
}
doc.AddPackage(sbom.PackageRef{Name: "my-lib", License: sbom.LicenseMIT})
```

## License

MIT — See [LICENSE](LICENSE) for details.
