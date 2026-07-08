// Package compare provides SBOM comparison functionality.
package compare

import (
	"fmt"
	"strings"

	"github.com/EdgarOrtegaRamirez/sbomforge/internal/sbom"
)

// DiffResult represents the difference between two SBOMs.
type DiffResult struct {
	Common      []string // Package names in both
	OnlyInLeft  []string // Packages only in SBOM A
	OnlyInRight []string // Packages only in SBOM B
	LicenseDiff []LicenseDiff
}

// LicenseDiff represents a license difference for a package.
type LicenseDiff struct {
	Package  string
	Left     string
	Right    string
}

// Diff compares two SBOMs and returns the differences.
func Diff(a, b *sbom.SBOM) *DiffResult {
	result := &DiffResult{}

	aNames := make(map[string]bool)
	bNames := make(map[string]bool)

	for _, pkg := range a.Packages {
		aNames[pkg.Name] = true
	}
	for _, pkg := range b.Packages {
		bNames[pkg.Name] = true
	}

	// Find common, only-in-left, only-in-right
	for name := range aNames {
		if bNames[name] {
			result.Common = append(result.Common, name)
		} else {
			result.OnlyInLeft = append(result.OnlyInLeft, name)
		}
	}
	for name := range bNames {
		if !aNames[name] {
			result.OnlyInRight = append(result.OnlyInRight, name)
		}
	}

	// Check license differences for common packages
	pkgLicenseA := make(map[string]string)
	pkgLicenseB := make(map[string]string)
	for _, pkg := range a.Packages {
		pkgLicenseA[pkg.Name] = string(pkg.License)
	}
	for _, pkg := range b.Packages {
		pkgLicenseB[pkg.Name] = string(pkg.License)
	}
	for _, name := range result.Common {
		if pkgLicenseA[name] != pkgLicenseB[name] {
			result.LicenseDiff = append(result.LicenseDiff, LicenseDiff{
				Package: name,
				Left:    pkgLicenseA[name],
				Right:   pkgLicenseB[name],
			})
		}
	}

	return result
}

// FormatDiff formats a DiffResult as a human-readable string.
func FormatDiff(result *DiffResult) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("SBOM Comparison Summary\n"))
	sb.WriteString(fmt.Sprintf("=======================\n"))
	sb.WriteString(fmt.Sprintf("Common packages:        %d\n", len(result.Common)))
	sb.WriteString(fmt.Sprintf("Only in source SBOM:    %d\n", len(result.OnlyInLeft)))
	sb.WriteString(fmt.Sprintf("Only in target SBOM:    %d\n", len(result.OnlyInRight)))
	sb.WriteString(fmt.Sprintf("License differences:    %d\n", len(result.LicenseDiff)))
	sb.WriteString("\n")

	if len(result.OnlyInLeft) > 0 {
		sb.WriteString("Removed packages:\n")
		for _, name := range result.OnlyInLeft {
			sb.WriteString(fmt.Sprintf("  - %s\n", name))
		}
		sb.WriteString("\n")
	}

	if len(result.OnlyInRight) > 0 {
		sb.WriteString("Added packages:\n")
		for _, name := range result.OnlyInRight {
			sb.WriteString(fmt.Sprintf("  + %s\n", name))
		}
		sb.WriteString("\n")
	}

	if len(result.LicenseDiff) > 0 {
		sb.WriteString("License changes:\n")
		for _, ld := range result.LicenseDiff {
			sb.WriteString(fmt.Sprintf("  %s: %s → %s\n", ld.Package, ld.Left, ld.Right))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// Merge combines two SBOMs into one.
func Merge(a, b *sbom.SBOM) *sbom.SBOM {
	merged := &sbom.SBOM{
		ID:          fmt.Sprintf("SPDXRef-%s", a.DocumentName),
		Name:        a.DocumentName,
		Version:     fmt.Sprintf("%s + %s", a.Version, b.Version),
		Creator:     fmt.Sprintf("%s + %s", a.Creator, b.Creator),
		Created:     a.Created,
		DataLicense: a.DataLicense,
		Namespace:   a.Namespace,
	}

	// Add all packages from A
	for _, pkg := range a.Packages {
		merged.Packages = append(merged.Packages, pkg)
	}
	// Add packages from B that aren't in A
	bNames := make(map[string]bool)
	for _, pkg := range a.Packages {
		bNames[pkg.Name] = true
	}
	for _, pkg := range b.Packages {
		if !bNames[pkg.Name] {
			merged.Packages = append(merged.Packages, pkg)
		}
	}

	return merged
}
