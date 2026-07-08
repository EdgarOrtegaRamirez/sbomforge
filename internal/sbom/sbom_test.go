package sbom

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"My Package", "my-package"},
		{"github.com/foo/bar", "github-com-foo-bar"},
		{"package.v1.0", "package-v1-0"},
		{"simple", "simple"},
	}

	for _, tt := range tests {
		result := normalizeID(tt.input)
		if result != tt.expected {
			t.Errorf("normalizeID(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestSBOMLicenseSummary(t *testing.T) {
	doc := &SBOM{
		Packages: []PackageRef{
			{Name: "pkg-a", License: LicenseMIT},
			{Name: "pkg-b", License: LicenseMIT},
			{Name: "pkg-c", License: LicenseApache20},
			{Name: "pkg-d", License: LicenseGPL30},
		},
	}

	summary := doc.LicenseSummary()
	if summary[LicenseMIT] != 2 {
		t.Errorf("expected 2 MIT packages, got %d", summary[LicenseMIT])
	}
	if summary[LicenseApache20] != 1 {
		t.Errorf("expected 1 Apache package, got %d", summary[LicenseApache20])
	}
	if summary[LicenseGPL30] != 1 {
		t.Errorf("expected 1 GPL package, got %d", summary[LicenseGPL30])
	}
}

func TestSBOMHasLicense(t *testing.T) {
	doc := &SBOM{
		Packages: []PackageRef{
			{Name: "pkg-a", License: LicenseMIT},
			{Name: "pkg-b", License: LicenseApache20},
		},
	}

	if !doc.HasLicense(LicenseMIT) {
		t.Error("expected HasLicense(MIT) to be true")
	}
	if !doc.HasLicense(LicenseApache20) {
		t.Error("expected HasLicense(Apache-2.0) to be true")
	}
	if doc.HasLicense(LicenseGPL30) {
		t.Error("expected HasLicense(GPL-3.0) to be false")
	}
}

func TestSBOMCopyleftPackages(t *testing.T) {
	doc := &SBOM{
		Packages: []PackageRef{
			{Name: "pkg-a", License: LicenseMIT},
			{Name: "pkg-b", License: LicenseGPL30},
			{Name: "pkg-c", License: LicenseApache20},
			{Name: "pkg-d", License: LicenseLGPL21},
			{Name: "pkg-e", License: LicenseBSD3Clause},
		},
	}

	copyleft := doc.CopyleftPackages()
	if len(copyleft) != 2 {
		t.Errorf("expected 2 copyleft packages, got %d", len(copyleft))
	}

	copyleftNames := make(map[string]bool)
	for _, pkg := range copyleft {
		copyleftNames[pkg.Name] = true
	}

	if !copyleftNames["pkg-b"] {
		t.Error("expected pkg-b (GPL-3.0) in copyleft list")
	}
	if !copyleftNames["pkg-d"] {
		t.Error("expected pkg-d (LGPL-2.1) in copyleft list")
	}
}

func TestSBOMHasCopyleft(t *testing.T) {
	doc1 := &SBOM{
		Packages: []PackageRef{
			{Name: "pkg-a", License: LicenseMIT},
		},
	}
	if doc1.HasCopyleft() {
		t.Error("expected HasCopyleft() to be false for non-copyleft packages")
	}

	doc2 := &SBOM{
		Packages: []PackageRef{
			{Name: "pkg-a", License: LicenseGPL30},
		},
	}
	if !doc2.HasCopyleft() {
		t.Error("expected HasCopyleft() to be true for GPL-3.0 package")
	}
}

func TestSBOMHasUnknownLicense(t *testing.T) {
	doc1 := &SBOM{
		Packages: []PackageRef{
			{Name: "pkg-a", License: LicenseMIT},
		},
	}
	if doc1.HasUnknownLicense() {
		t.Error("expected HasUnknownLicense() to be false")
	}

	doc2 := &SBOM{
		Packages: []PackageRef{
			{Name: "pkg-a", License: LicenseUnknown},
		},
	}
	if !doc2.HasUnknownLicense() {
		t.Error("expected HasUnknownLicense() to be true for UNKNOWN")
	}

	doc3 := &SBOM{
		Packages: []PackageRef{
			{Name: "pkg-a", License: LicenseNone},
		},
	}
	if !doc3.HasUnknownLicense() {
		t.Error("expected HasUnknownLicense() to be true for NONE")
	}
}

func TestComputeStringSHA256(t *testing.T) {
	hash1 := ComputeStringSHA256("hello")
	hash2 := ComputeStringSHA256("hello")
	hash3 := ComputeStringSHA256("world")

	if hash1 != hash2 {
		t.Error("same input should produce same hash")
	}
	if hash1 == hash3 {
		t.Error("different input should produce different hash")
	}
	if len(hash1) != 64 {
		t.Errorf("expected SHA-256 hash length 64, got %d", len(hash1))
	}
}

func TestComputeFileSHA256(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatal(err)
	}

	hash, err := ComputeFileSHA256(testFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hash) != 64 {
		t.Errorf("expected SHA-256 hash length 64, got %d", len(hash))
	}

	// Test with non-existent file
	_, err = ComputeFileSHA256(filepath.Join(tmpDir, "nonexistent.txt"))
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestScanDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	// Create some files
	os.MkdirAll(filepath.Join(tmpDir, "subdir"), 0755)
	os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("content1"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "subdir", "file2.txt"), []byte("content2"), 0644)

	files, err := ScanDirectory(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(files) != 3 { // file1.txt, subdir/, subdir/file2.txt
		t.Errorf("expected 3 entries, got %d", len(files))
	}

	// Verify directory is marked as such
	for _, f := range files {
		if f.Path == "subdir" && !f.IsDir {
			t.Error("expected subdir to be a directory")
		}
	}
}

func TestSBOMAnalyzeDependencies(t *testing.T) {
	doc := &SBOM{
		Packages: []PackageRef{
			{Name: "app"},
			{Name: "lib-a"},
			{Name: "lib-b"},
		},
	}

	deps := map[string][]string{
		"app":   {"lib-a", "lib-b"},
		"lib-a": {},
		"lib-b": {},
	}

	doc.AnalyzeDependencies(deps)

	if len(doc.Dependencies) != 2 {
		t.Errorf("expected 2 dependencies, got %d", len(doc.Dependencies))
	}

	// Verify dependency relationships
	depMap := make(map[string]string)
	for _, dep := range doc.Dependencies {
		depMap[dep.SPDXRefPackage] = dep.DependsOn
	}

	if _, ok := depMap["SPDXRef-app"]; !ok {
		t.Error("expected app to have dependencies")
	}
}

func TestSBOMAddPackage(t *testing.T) {
	doc := &SBOM{}
	doc.AddPackage(PackageRef{Name: "test-pkg", License: LicenseMIT})

	if len(doc.Packages) != 1 {
		t.Errorf("expected 1 package, got %d", len(doc.Packages))
	}
	if doc.Packages[0].Name != "test-pkg" {
		t.Errorf("expected package name 'test-pkg', got %q", doc.Packages[0].Name)
	}
}
