// Package sbom provides SPDX 2.3 compliant Software Bill of Materials generation.
package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// LicenseType represents a software license.
type LicenseType string

const (
	LicenseMIT           LicenseType = "MIT"
	LicenseApache20      LicenseType = "Apache-2.0"
	LicenseGPL30         LicenseType = "GPL-3.0-only"
	LicenseGPL20         LicenseType = "GPL-2.0-only"
	LicenseBSD2Clause    LicenseType = "BSD-2-Clause"
	LicenseBSD3Clause    LicenseType = "BSD-3-Clause"
	LicenseISC           LicenseType = "ISC"
	LicenseMPL20         LicenseType = "MPL-2.0"
	LicenseLGPL30        LicenseType = "LGPL-3.0-only"
	LicenseLGPL21        LicenseType = "LGPL-2.1-only"
	LicenseAGPL30        LicenseType = "AGPL-3.0-only"
	LicensePrivate       LicenseType = "PRIVATE"
	LicenseUnknown       LicenseType = "NOASSERTION"
	LicenseNone          LicenseType = "NONE"
)

// PackageRef represents a software package in the SBOM.
type PackageRef struct {
	Name       string     `json:"name"`
	Version    string     `json:"version,omitempty"`
	Supplier   string     `json:"supplier,omitempty"`
	License    LicenseType `json:"licenseConcluded"`
	SourceInfo string     `json:"sourceInfo,omitempty"`
	FilesAnalyzed bool    `json:"filesAnalyzed"`
	HomePage   string     `json:"homepage,omitempty"`
	Summary    string     `json:"summary,omitempty"`
	DownloadURL string    `json:"downloadLocation,omitempty"`
	Sha256     string     `json:"sha256,omitempty"`
}

// SBOM represents a complete Software Bill of Materials.
type SBOM struct {
	ID           string        `json:"SPDXID"`
	Name         string        `json:"name"`
	Version      string        `json:"version"`
	Creator      string        `json:"creator"`
	Created      string        `json:"created"`
	DataLicense  string        `json:"dataLicense"`
	DocumentName string        `json:"documentName"`
	Namespace    string        `json:"documentNamespace"`
	Packages     []PackageRef  `json:"packages,omitempty"`
	Dependencies []Dependency  `json:"relationships,omitempty"`
}

// Dependency represents a relationship between packages.
type Dependency struct {
	SPDXRefPackage string `json:"spdxId"`
	DependsOn      string `json:"dependsOn"`
	Relationship   string `json:"relationshipType"`
}

// AnalyzeDependencies analyzes the dependency graph and generates SPDX relationships.
func (s *SBOM) AnalyzeDependencies(deps map[string][]string) {
	// Create a map of package SPDX IDs
	pkgIDs := make(map[string]string)
	for _, pkg := range s.Packages {
		id := fmt.Sprintf("SPDXRef-%s", normalizeID(pkg.Name))
		pkgIDs[pkg.Name] = id
	}

	// Generate dependency relationships
	for pkgName, depNames := range deps {
		pkgID, ok := pkgIDs[pkgName]
		if !ok {
			continue
		}
		for _, depName := range depNames {
			depID, ok := pkgIDs[depName]
			if !ok {
				continue
			}
			s.Dependencies = append(s.Dependencies, Dependency{
				SPDXRefPackage: pkgID,
				DependsOn:      depID,
				Relationship:   "DEPENDS_ON",
			})
		}
	}
}

// AddPackage adds a package to the SBOM.
func (s *SBOM) AddPackage(pkg PackageRef) {
	s.Packages = append(s.Packages, pkg)
}

// AddDependency adds a dependency relationship.
func (s *SBOM) AddDependency(dep Dependency) {
	s.Dependencies = append(s.Dependencies, dep)
}

// HasLicense checks if the SBOM contains packages with specific license types.
func (s *SBOM) HasLicense(license LicenseType) bool {
	for _, pkg := range s.Packages {
		if pkg.License == license {
			return true
		}
	}
	return false
}

// LicenseSummary returns a count of packages by license.
func (s *SBOM) LicenseSummary() map[LicenseType]int {
	summary := make(map[LicenseType]int)
	for _, pkg := range s.Packages {
		summary[pkg.License]++
	}
	return summary
}

// CopyleftPackages returns packages with copyleft licenses.
func (s *SBOM) CopyleftPackages() []PackageRef {
	copyleft := map[LicenseType]bool{
		LicenseGPL30: true, LicenseGPL20: true,
		LicenseLGPL30: true, LicenseLGPL21: true,
		LicenseAGPL30: true, LicenseMPL20: true,
	}
	var result []PackageRef
	for _, pkg := range s.Packages {
		if copyleft[pkg.License] {
			result = append(result, pkg)
		}
	}
	return result
}

// HasCopyleft returns true if any package has a copyleft license.
func (s *SBOM) HasCopyleft() bool {
	return len(s.CopyleftPackages()) > 0
}

// HasUnknownLicense returns true if any package has an unknown license.
func (s *SBOM) HasUnknownLicense() bool {
	for _, pkg := range s.Packages {
		if pkg.License == LicenseUnknown || pkg.License == LicenseNone {
			return true
		}
	}
	return false
}

// NormalizeID creates a valid SPDX identifier from a name.
func normalizeID(name string) string {
	id := strings.ToLower(name)
	id = strings.ReplaceAll(id, " ", "-")
	id = strings.ReplaceAll(id, "/", "-")
	id = strings.ReplaceAll(id, ".", "-")
	// Remove invalid characters
	var result strings.Builder
	for _, c := range id {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			result.WriteByte(byte(c))
		}
	}
	return result.String()
}

// ComputeFileSHA256 computes the SHA-256 hash of a file.
func ComputeFileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// ComputeStringSHA256 computes the SHA-256 hash of a string.
func ComputeStringSHA256(s string) string {
	hash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hash[:])
}

// FileMeta holds metadata about a scanned file.
type FileMeta struct {
	Path     string
	IsDir    bool
	Size     int64
	Modified time.Time
	Mode     os.FileMode
}

// ScanDirectory scans a directory and returns file metadata.
func ScanDirectory(root string) ([]FileMeta, error) {
	var files []FileMeta
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if rel == "." {
			return nil
		}
		files = append(files, FileMeta{
			Path:     rel,
			IsDir:    info.IsDir(),
			Size:     info.Size(),
			Modified: info.ModTime(),
			Mode:     info.Mode(),
		})
		return nil
	})
	return files, err
}
