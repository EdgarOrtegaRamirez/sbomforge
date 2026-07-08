// Package main provides the SBOMForge CLI.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/EdgarOrtegaRamirez/sbomforge/internal/compare"
	"github.com/EdgarOrtegaRamirez/sbomforge/internal/parsers"
	"github.com/EdgarOrtegaRamirez/sbomforge/internal/sbom"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "generate":
		cmdGenerate(args)
	case "parse":
		cmdParse(args)
	case "compare":
		cmdCompare(args)
	case "info":
		cmdInfo(args)
	case "licenses":
		cmdLicenses(args)
	case "version":
		fmt.Printf("sbomforge version %s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`SBOMForge — Software Bill of Materials Toolkit

Usage:
  sbomforge <command> [arguments]

Commands:
  generate   Generate an SBOM from a project directory
  parse      Parse and display an existing SBOM (SPDX/CycloneDX)
  compare    Compare two SBOMs
  info       Display quick SBOM information
  licenses   Analyze license distribution
  version    Show version`)
}

func cmdGenerate(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: sbomforge generate <directory>")
		os.Exit(1)
	}

	root := args[0]
	format := "spdx"
	if len(args) > 1 {
		format = strings.ToLower(args[1])
	}

	// Scan directory for packages
	packages, deps := scanProject(root)

	// Create SBOM
	timestamp := "2026-01-01T00:00:00Z"
	ns := fmt.Sprintf("https://sbomforge.local/project/%s/%s", sanitizeName(root), timestamp)

	doc := &sbom.SBOM{
		ID:           "SPDXRef-DOCUMENT",
		Name:         sanitizeName(root),
		Version:      "1.0.0",
		Creator:      fmt.Sprintf("Tool: sbomforge-%s", version),
		Created:      timestamp,
		DataLicense:  "CC0-1.0",
		DocumentName: sanitizeName(root),
		Namespace:    ns,
	}

	// Add packages
	for _, pkg := range packages {
		doc.AddPackage(pkg)
	}

	// Analyze dependencies
	doc.AnalyzeDependencies(deps)

	// Output
	switch format {
	case "cyclonedx":
		outputCycloneDX(doc)
	default:
		outputSPDX(doc)
	}
}

func cmdParse(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: sbomforge parse <sbom-file>")
		os.Exit(1)
	}

	path := args[0]
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	format := parsers.DetectFormat(data)
	fmt.Printf("Detected format: %s\n\n", format)

	switch format {
	case "spdx":
		var doc parsers.SPDXDocument
		if err := json.Unmarshal(data, &doc); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing SPDX: %v\n", err)
			os.Exit(1)
		}
		printSPDXSummary(&doc)
	case "cyclonedx":
		var doc parsers.CycloneDXDocument
		if err := json.Unmarshal(data, &doc); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing CycloneDX: %v\n", err)
			os.Exit(1)
		}
		printCycloneDXSummary(&doc)
	default:
		fmt.Fprintln(os.Stderr, "Unknown SBOM format")
		os.Exit(1)
	}
}

func cmdCompare(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: sbomforge compare <sbom-a> <sbom-b>")
		os.Exit(1)
	}

	dataA, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", args[0], err)
		os.Exit(1)
	}
	dataB, err := os.ReadFile(args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", args[1], err)
		os.Exit(1)
	}

	fmtA := parsers.DetectFormat(dataA)
	fmtB := parsers.DetectFormat(dataB)
	fmt.Printf("Format A: %s\nFormat B: %s\n\n", fmtA, fmtB)

	// Convert both to SBOM format
	sbomA := convertToSBOM(dataA, fmtA)
	sbomB := convertToSBOM(dataB, fmtB)

	if sbomA == nil || sbomB == nil {
		fmt.Fprintln(os.Stderr, "Failed to parse one or both SBOMs")
		os.Exit(1)
	}

	result := compare.Diff(sbomA, sbomB)
	fmt.Print(compare.FormatDiff(result))
}

func cmdInfo(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: sbomforge info <sbom-file>")
		os.Exit(1)
	}

	data, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	format := parsers.DetectFormat(data)
	fmt.Printf("Format: %s\n", format)

	sbomDoc := convertToSBOM(data, format)
	if sbomDoc == nil {
		fmt.Fprintln(os.Stderr, "Failed to parse SBOM")
		os.Exit(1)
	}

	summary := sbomDoc.LicenseSummary()
	fmt.Printf("Packages: %d\n", len(sbomDoc.Packages))
	fmt.Printf("License summary:\n")
	for lic, count := range summary {
		fmt.Printf("  %s: %d\n", lic, count)
	}

	if sbomDoc.HasCopyleft() {
		fmt.Println("\n⚠  Copyleft licenses detected:")
		for _, pkg := range sbomDoc.CopyleftPackages() {
			fmt.Printf("  ⚠  %s (%s)\n", pkg.Name, pkg.License)
		}
	}

	if sbomDoc.HasUnknownLicense() {
		fmt.Println("\n⚠  Unknown licenses detected:")
		for _, pkg := range sbomDoc.Packages {
			if pkg.License == sbom.LicenseUnknown || pkg.License == sbom.LicenseNone {
				fmt.Printf("  ⚠  %s\n", pkg.Name)
			}
		}
	}
}

func cmdLicenses(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: sbomforge licenses <sbom-file>")
		os.Exit(1)
	}

	data, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	sbomDoc := convertToSBOM(data, parsers.DetectFormat(data))
	if sbomDoc == nil {
		fmt.Fprintln(os.Stderr, "Failed to parse SBOM")
		os.Exit(1)
	}

	summary := sbomDoc.LicenseSummary()
	total := len(sbomDoc.Packages)

	fmt.Println("License Distribution")
	fmt.Println("====================")
	for lic, count := range summary {
		pct := float64(count) / float64(total) * 100
		bar := strings.Repeat("█", int(pct/5))
		fmt.Printf("%-15s %3d (%5.1f%%) %s\n", lic, count, pct, bar)
	}

	fmt.Println()
	if sbomDoc.HasCopyleft() {
		fmt.Printf("⚠  Copyleft packages: %d\n", len(sbomDoc.CopyleftPackages()))
	}
}

func convertToSBOM(data []byte, format string) *sbom.SBOM {
	if format == "spdx" {
		var doc parsers.SPDXDocument
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil
		}
		sbomDoc := &sbom.SBOM{
			ID:           doc.SPDXID,
			Name:         doc.Name,
			Version:      doc.Version,
			Creator:      strings.Join(doc.CreationInfo.Creators, ", "),
			Created:      doc.CreationInfo.Created,
			DataLicense:  "CC0-1.0",
			DocumentName: doc.Name,
		}
		for _, pkg := range doc.Packages {
			sbomDoc.AddPackage(sbom.PackageRef{
				Name:       pkg.Name,
				Version:    pkg.VersionInfo,
				License:    sbom.LicenseType(pkg.LicenseConcluded),
				FilesAnalyzed: pkg.FilesAnalyzed,
				HomePage:   pkg.Homepage,
				DownloadURL: pkg.DownloadLocation,
			})
		}
		return sbomDoc
	}

	if format == "cyclonedx" {
		var doc parsers.CycloneDXDocument
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil
		}
		sbomDoc := &sbom.SBOM{
			ID:          fmt.Sprintf("SPDXRef-%s", sanitizeName("cdx")),
			Name:        sanitizeName("cdx"),
			Version:     fmt.Sprintf("%d", doc.Version),
			Creator:     strings.Join(doc.Metadata.Tools, ", "),
			Created:     doc.Metadata.Timestamp,
			DataLicense: "CC0-1.0",
			DocumentName: sanitizeName("cdx"),
		}
		for _, comp := range doc.Components {
			lic := string(sbom.LicenseUnknown)
			if len(comp.Licenses) > 0 {
				lic = comp.Licenses[0].ID
			}
			sbomDoc.AddPackage(sbom.PackageRef{
				Name:       comp.Name,
				Version:    comp.Version,
				License:    sbom.LicenseType(lic),
				FilesAnalyzed: false,
				DownloadURL: comp.Purl,
			})
		}
		return sbomDoc
	}

	return nil
}

func scanProject(root string) ([]sbom.PackageRef, map[string][]string) {
	// Simple scan: detect lock files and create package references
	var packages []sbom.PackageRef
	var deps = make(map[string][]string)

	// Look for common lock files
	lockFiles := map[string]string{
		"go.sum":        "go",
		"package-lock.json": "npm",
		"yarn.lock":     "npm",
		"requirements.txt": "python",
		"pyproject.toml": "python",
		"cargo.lock":    "rust",
		"Gemfile.lock":  "ruby",
		"composer.lock": "php",
	}

	found := false
	for lockFile, lang := range lockFiles {
		path := root + "/" + lockFile
		if _, err := os.Stat(path); err == nil {
			found = true
			packages = append(packages, sbom.PackageRef{
				Name:       lockFile,
				SourceInfo: lang + "-lockfile",
				License:    sbom.LicenseNone,
			})
		}
	}

	// If no lock files found, create a placeholder
	if !found {
		packages = append(packages, sbom.PackageRef{
			Name:       root + "/project",
			SourceInfo: "auto-generated",
			License:    sbom.LicenseUnknown,
		})
	}

	return packages, deps
}

func printSPDXSummary(doc *parsers.SPDXDocument) {
	fmt.Printf("SPDX Document: %s\n", doc.Name)
	fmt.Printf("Version: %s\n", doc.Version)
	fmt.Printf("Created: %s\n", doc.CreationInfo.Created)
	fmt.Printf("Creators: %s\n", strings.Join(doc.CreationInfo.Creators, ", "))
	fmt.Printf("Packages: %d\n", len(doc.Packages))
	fmt.Printf("Relationships: %d\n\n", len(doc.Relationships))

	fmt.Println("Packages:")
	for _, pkg := range doc.Packages {
		fmt.Printf("  %-30s v%-15s [%s]\n", pkg.Name, pkg.VersionInfo, pkg.LicenseConcluded)
	}
}

func printCycloneDXSummary(doc *parsers.CycloneDXDocument) {
	fmt.Printf("CycloneDX Document v%d\n", doc.Version)
	fmt.Printf("Tools: %s\n", strings.Join(doc.Metadata.Tools, ", "))
	fmt.Printf("Components: %d\n", len(doc.Components))
	fmt.Printf("Dependencies: %d\n\n", len(doc.Dependencies))

	fmt.Println("Components:")
	for _, comp := range doc.Components {
		lic := "unknown"
		if len(comp.Licenses) > 0 {
			lic = comp.Licenses[0].ID
		}
		fmt.Printf("  %-30s v%-15s [%s] (type: %s)\n",
			comp.Name, comp.Version, lic, comp.Type)
	}
}

func sanitizeName(name string) string {
	name = strings.Trim(name, "/")
	name = strings.ReplaceAll(name, "/", "-")
	name = strings.ReplaceAll(name, " ", "-")
	if name == "" {
		return "project"
	}
	return name
}

func outputSPDX(doc *sbom.SBOM) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding SPDX: %v\n", err)
		os.Exit(1)
	}
}

func outputCycloneDX(doc *sbom.SBOM) {
	type CDXComponent struct {
		BOMRef       string   `json:"bom-ref"`
		Name         string   `json:"name"`
		Version      string   `json:"version,omitempty"`
		Type         string   `json:"type"`
		Licenses     []string `json:"licenses,omitempty"`
		ExternalRefs []struct {
			RefType string `json:"refType"`
			URL     string `json:"url"`
		} `json:"externalRefs,omitempty"`
		Purl string `json:"purl,omitempty"`
	}

	type CDXDoc struct {
		Version    int              `json:"version"`
		Components []CDXComponent   `json:"components"`
	}

	components := make([]CDXComponent, len(doc.Packages))
	for i, pkg := range doc.Packages {
		comp := CDXComponent{
			BOMRef: fmt.Sprintf("pkg-%d", i),
			Name:   pkg.Name,
			Type:   "library",
		}
		if pkg.Version != "" {
			comp.Version = pkg.Version
		}
		if pkg.License != sbom.LicenseNone && pkg.License != sbom.LicenseUnknown {
			comp.Licenses = []string{string(pkg.License)}
		}
		components[i] = comp
	}

	cdx := CDXDoc{
		Version:    1,
		Components: components,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cdx); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding CycloneDX: %v\n", err)
		os.Exit(1)
	}
}
