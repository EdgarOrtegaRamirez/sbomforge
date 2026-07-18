// Package parsers provides SPDX 2.3 JSON and CycloneDX 1.5 JSON parsers.
package parsers

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// SPDXParser parses SPDX 2.3 JSON documents.
type SPDXParser struct{}

// SPDXDocument represents the root of an SPDX 2.3 document.
type SPDXDocument struct {
	SPDXID        string         `json:"spdxId"`
	Name          string         `json:"name"`
	Version       string         `json:"spdxVersion"`
	CreationInfo  CreationInfo   `json:"creationInfo"`
	Packages      []SPDXPackage  `json:"packages"`
	Relationships []Relationship `json:"relationships"`
}

// CreationInfo represents the SPDX document creation metadata.
type CreationInfo struct {
	Created     string   `json:"created"`
	Creators    []string `json:"creators"`
	ListVersion int      `json:"listVersion,omitempty"`
}

// SPDXPackage represents a package in an SPDX document.
type SPDXPackage struct {
	SPDXID           string `json:"spdxId"`
	Name             string `json:"name"`
	VersionInfo      string `json:"versionInfo,omitempty"`
	DownloadLocation string `json:"downloadLocation"`
	LicenseConcluded string `json:"licenseConcluded"`
	LicenseDeclared  string `json:"licenseDeclared,omitempty"`
	FilesAnalyzed    bool   `json:"filesAnalyzed"`
	Supplier         string `json:"supplier,omitempty"`
	Homepage         string `json:"homepage,omitempty"`
}

// Relationship represents a relationship between SPDX elements.
type Relationship struct {
	SPDXRefFrom  string `json:"spdxRefFrom"`
	SPDXRefTo    string `json:"spdxRefTo,omitempty"`
	Relationship string `json:"relationshipType"`
}

// ParseSPDX parses an SPDX 2.3 JSON document from a file.
func (p *SPDXParser) Parse(path string) (*SPDXDocument, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read SPDX file: %w", err)
	}
	return p.ParseBytes(data)
}

// ParseBytes parses an SPDX 2.3 JSON document from bytes.
func (p *SPDXParser) ParseBytes(data []byte) (*SPDXDocument, error) {
	var doc SPDXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse SPDX JSON: %w", err)
	}
	if doc.SPDXID == "" {
		return nil, fmt.Errorf("invalid SPDX document: missing spdxId")
	}
	return &doc, nil
}

// CycloneDXParser parses CycloneDX 1.5 JSON documents.
type CycloneDXParser struct{}

// CycloneDXDocument represents a CycloneDX 1.5 document.
type CycloneDXDocument struct {
	Version      int          `json:"version"`
	Metadata     Metadata     `json:"metadata,omitempty"`
	Components   []Component  `json:"components"`
	Dependencies []CycloneDep `json:"dependencies,omitempty"`
}

// Metadata holds document creation metadata.
type Metadata struct {
	Timestamp string   `json:"timestamp,omitempty"`
	Tools     []string `json:"tools,omitempty"`
}

// Component represents a software component.
type Component struct {
	BOMRef       string        `json:"bom-ref"`
	Name         string        `json:"name"`
	Version      string        `json:"version,omitempty"`
	Type         string        `json:"type"`
	Licenses     []LicenseRef  `json:"licenses,omitempty"`
	ExternalRefs []ExternalRef `json:"externalRefs,omitempty"`
	Purl         string        `json:"purl,omitempty"`
}

// LicenseRef represents a license in CycloneDX.
type LicenseRef struct {
	ID string `json:"id"`
}

// ExternalRef represents an external reference.
type ExternalRef struct {
	RefType string `json:"refType"`
	URL     string `json:"url"`
}

// CycloneDep represents a CycloneDX dependency.
type CycloneDep struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

// ParseCycloneDX parses a CycloneDX 1.5 JSON document from a file.
func (p *CycloneDXParser) Parse(path string) (*CycloneDXDocument, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CycloneDX file: %w", err)
	}
	return p.ParseBytes(data)
}

// ParseBytes parses a CycloneDX 1.5 JSON document from bytes.
func (p *CycloneDXParser) ParseBytes(data []byte) (*CycloneDXDocument, error) {
	var doc CycloneDXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse CycloneDX JSON: %w", err)
	}
	if doc.Version < 1 || doc.Version > 10 {
		return nil, fmt.Errorf("unsupported CycloneDX version: %d", doc.Version)
	}
	return &doc, nil
}

// DetectFormat detects the SBOM format from content.
func DetectFormat(data []byte) string {
	trimmed := strings.TrimSpace(string(data))
	if !strings.HasPrefix(trimmed, "{") {
		return "unknown"
	}

	// Check SPDX first
	var spdx map[string]interface{}
	if err := json.Unmarshal([]byte(trimmed), &spdx); err == nil {
		if _, ok := spdx["spdxId"]; ok {
			return "spdx"
		}
	}

	// Check CycloneDX
	var cdx map[string]interface{}
	if err := json.Unmarshal([]byte(trimmed), &cdx); err == nil {
		if _, ok := cdx["bomFormat"]; ok {
			return "cyclonedx"
		}
	}

	return "unknown"
}
