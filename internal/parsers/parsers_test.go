package parsers

import (
	"testing"
)

func TestDetectFormatSPDX(t *testing.T) {
	data := []byte(`{"spdxId": "SPDXRef-DOCUMENT", "name": "test", "spdxVersion": "SPDX-2.3"}`)
	format := DetectFormat(data)
	if format != "spdx" {
		t.Errorf("expected spdx, got %s", format)
	}
}

func TestDetectFormatCycloneDX(t *testing.T) {
	data := []byte(`{"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1}`)
	format := DetectFormat(data)
	if format != "cyclonedx" {
		t.Errorf("expected cyclonedx, got %s", format)
	}
}

func TestDetectFormatUnknown(t *testing.T) {
	data := []byte(`{"some": "json"}`)
	format := DetectFormat(data)
	if format != "unknown" {
		t.Errorf("expected unknown, got %s", format)
	}
}

func TestDetectFormatNonJSON(t *testing.T) {
	data := []byte("not json at all")
	format := DetectFormat(data)
	if format != "unknown" {
		t.Errorf("expected unknown, got %s", format)
	}
}

func TestSPDXParserParseBytes(t *testing.T) {
	data := []byte(`{
		"spdxId": "SPDXRef-DOCUMENT",
		"name": "test-doc",
		"spdxVersion": "SPDX-2.3",
		"creationInfo": {
			"created": "2026-01-01T00:00:00Z",
			"creators": ["Tool: test"]
		},
		"packages": []
	}`)

	parser := &SPDXParser{}
	doc, err := parser.ParseBytes(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if doc.SPDXID != "SPDXRef-DOCUMENT" {
		t.Errorf("expected SPDXRef-DOCUMENT, got %s", doc.SPDXID)
	}
	if doc.Name != "test-doc" {
		t.Errorf("expected test-doc, got %s", doc.Name)
	}
}

func TestSPDXParserParseInvalid(t *testing.T) {
	parser := &SPDXParser{}
	_, err := parser.ParseBytes([]byte(`{}`))
	if err == nil {
		t.Error("expected error for missing spdxId")
	}
}

func TestCycloneDXParserParseBytes(t *testing.T) {
	data := []byte(`{
		"version": 1,
		"metadata": {
			"timestamp": "2026-01-01T00:00:00Z",
			"tools": ["sbomforge"]
		},
		"components": []
	}`)

	parser := &CycloneDXParser{}
	doc, err := parser.ParseBytes(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if doc.Version != 1 {
		t.Errorf("expected version 1, got %d", doc.Version)
	}
}

func TestCycloneDXParserInvalidVersion(t *testing.T) {
	parser := &CycloneDXParser{}
	_, err := parser.ParseBytes([]byte(`{"version": 99}`))
	if err == nil {
		t.Error("expected error for invalid version")
	}
}
