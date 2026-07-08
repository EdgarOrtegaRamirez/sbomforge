package compare

import (
	"testing"

	"github.com/EdgarOrtegaRamirez/sbomforge/internal/sbom"
)

func TestDiff(t *testing.T) {
	a := &sbom.SBOM{
		Packages: []sbom.PackageRef{
			{Name: "pkg-a", License: sbom.LicenseMIT},
			{Name: "pkg-b", License: sbom.LicenseMIT},
			{Name: "pkg-c", License: sbom.LicenseApache20},
		},
	}
	b := &sbom.SBOM{
		Packages: []sbom.PackageRef{
			{Name: "pkg-b", License: sbom.LicenseMIT},
			{Name: "pkg-c", License: sbom.LicenseGPL30},
			{Name: "pkg-d", License: sbom.LicenseMIT},
		},
	}

	result := Diff(a, b)

	if len(result.Common) != 2 {
		t.Errorf("expected 2 common packages, got %d", len(result.Common))
	}
	if len(result.OnlyInLeft) != 1 {
		t.Errorf("expected 1 only-in-left, got %d", len(result.OnlyInLeft))
	}
	if len(result.OnlyInRight) != 1 {
		t.Errorf("expected 1 only-in-right, got %d", len(result.OnlyInRight))
	}
	if len(result.LicenseDiff) != 1 {
		t.Errorf("expected 1 license diff, got %d", len(result.LicenseDiff))
	}

	// Verify specific results
	common := make(map[string]bool)
	for _, name := range result.Common {
		common[name] = true
	}
	if !common["pkg-b"] || !common["pkg-c"] {
		t.Error("expected pkg-b and pkg-c in common")
	}

	if len(result.OnlyInLeft) != 1 || result.OnlyInLeft[0] != "pkg-a" {
		t.Error("expected only-in-left to contain pkg-a")
	}
	if len(result.OnlyInRight) != 1 || result.OnlyInRight[0] != "pkg-d" {
		t.Error("expected only-in-right to contain pkg-d")
	}

	// License diff should show pkg-c changed from Apache-2.0 to GPL-3.0
	if result.LicenseDiff[0].Package != "pkg-c" {
		t.Errorf("expected license diff for pkg-c, got %s", result.LicenseDiff[0].Package)
	}
}

func TestDiffEmpty(t *testing.T) {
	a := &sbom.SBOM{}
	b := &sbom.SBOM{}

	result := Diff(a, b)

	if len(result.Common) != 0 || len(result.OnlyInLeft) != 0 || len(result.OnlyInRight) != 0 {
		t.Error("expected empty diff for empty SBOMs")
	}
}

func TestDiffIdentical(t *testing.T) {
	pkg := sbom.PackageRef{Name: "pkg-a", License: sbom.LicenseMIT}
	a := &sbom.SBOM{Packages: []sbom.PackageRef{pkg}}
	b := &sbom.SBOM{Packages: []sbom.PackageRef{pkg}}

	result := Diff(a, b)

	if len(result.Common) != 1 {
		t.Errorf("expected 1 common package, got %d", len(result.Common))
	}
	if len(result.OnlyInLeft) != 0 || len(result.OnlyInRight) != 0 {
		t.Error("expected no differences for identical SBOMs")
	}
	if len(result.LicenseDiff) != 0 {
		t.Error("expected no license diffs for identical SBOMs")
	}
}

func TestFormatDiff(t *testing.T) {
	a := &sbom.SBOM{
		Packages: []sbom.PackageRef{
			{Name: "pkg-a", License: sbom.LicenseMIT},
		},
	}
	b := &sbom.SBOM{
		Packages: []sbom.PackageRef{
			{Name: "pkg-b", License: sbom.LicenseMIT},
		},
	}

	result := Diff(a, b)
	output := FormatDiff(result)

	if len(output) == 0 {
		t.Error("expected non-empty diff output")
	}
}

func TestMerge(t *testing.T) {
	a := &sbom.SBOM{
		Packages: []sbom.PackageRef{
			{Name: "pkg-a", License: sbom.LicenseMIT},
			{Name: "pkg-b", License: sbom.LicenseMIT},
		},
	}
	b := &sbom.SBOM{
		Packages: []sbom.PackageRef{
			{Name: "pkg-b", License: sbom.LicenseMIT},
			{Name: "pkg-c", License: sbom.LicenseApache20},
		},
	}

	merged := Merge(a, b)

	if len(merged.Packages) != 3 {
		t.Errorf("expected 3 packages in merged SBOM, got %d", len(merged.Packages))
	}

	names := make(map[string]bool)
	for _, pkg := range merged.Packages {
		names[pkg.Name] = true
	}

	if !names["pkg-a"] || !names["pkg-b"] || !names["pkg-c"] {
		t.Error("expected all 3 packages in merged SBOM")
	}
}
