package strangelove

import (
	"bufio"
	"bytes"
	"io"
	"strings"
)

const defaultPeekSize = 4096 // 4 KB — enough to read any SBOM header for identification

// Identifier peeks at the beginning of an SBOM stream to detect its format,
// standard, serialization, and specification version.
type Identifier struct {
	peekSize int
}

type identifierOption func(*Identifier)

// WithPeekSize sets the number of bytes peeked for format detection.
// The default is 4096 bytes.
func WithPeekSize(size int) identifierOption {
	return func(id *Identifier) {
		id.peekSize = size
	}
}

// NewIdentifier creates an Identifier with the given options.
func NewIdentifier(opts ...identifierOption) *Identifier {
	id := &Identifier{peekSize: defaultPeekSize}
	for _, opt := range opts {
		opt(id)
	}
	return id
}

// IdentificationResult contains the detected format and a buffered reader
// that preserves the stream position past the peeked bytes.
type IdentificationResult struct {
	Format SBOMFormat
	Reader *bufio.Reader
}

// Identify reads the peek buffer, detects the SBOM format, and returns the
// result along with a buffered reader ready to consume the full stream.
func (id *Identifier) Identify(r io.Reader) (IdentificationResult, error) {
	br, ok := r.(*bufio.Reader)
	if !ok || br.Size() < id.peekSize {
		br = bufio.NewReaderSize(r, id.peekSize)
	}

	peek, err := br.Peek(id.peekSize)
	if err != nil && err != io.EOF {
		return IdentificationResult{}, err
	}

	if len(peek) == 0 {
		return IdentificationResult{}, ErrEmptyInput
	}

	switch {
	case isJSON(peek):
		std, ver := detectJSONSBOMStandard(peek)
		if std == SBOMStandardUnknown {
			return IdentificationResult{}, ErrUnknownFormat
		}
		return IdentificationResult{Format: SBOMFormat{SBOMStandard: std, Serialization: SerializationJSON, SpecVersion: ver}, Reader: br}, nil

	case isXML(peek):
		if isRDF(peek) {
			std, ver := detectRDFStandard(peek)
			if std == SBOMStandardUnknown {
				return IdentificationResult{}, ErrUnknownFormat
			}
			return IdentificationResult{Format: SBOMFormat{SBOMStandard: std, Serialization: SerializationRDF, SpecVersion: ver}, Reader: br}, nil
		}
		std, ver := detectXMLSBOMStandard(peek)
		if std == SBOMStandardUnknown {
			return IdentificationResult{}, ErrUnknownFormat
		}
		return IdentificationResult{Format: SBOMFormat{SBOMStandard: std, Serialization: SerializationXML, SpecVersion: ver}, Reader: br}, nil

	case isTagValue(peek):
		std, ver := detectTagValueSBOMStandard(peek)
		if std == SBOMStandardUnknown {
			return IdentificationResult{}, ErrUnknownFormat
		}
		return IdentificationResult{Format: SBOMFormat{SBOMStandard: std, Serialization: SerializationSPDXTagValue, SpecVersion: ver}, Reader: br}, nil

	default:
		return IdentificationResult{}, ErrUnknownFormat
	}
}

func isJSON(data []byte) bool {
	data = bytes.TrimSpace(data)
	return len(data) > 0 && data[0] == '{'
}

func isXML(data []byte) bool {
	data = bytes.TrimSpace(data)
	return bytes.HasPrefix(data, []byte("<"))
}

func isTagValue(data []byte) bool {
	lines := bytes.Split(data, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if bytes.HasPrefix(line, []byte("SPDXVersion:")) ||
			bytes.HasPrefix(line, []byte("##")) {
			return true
		}
	}
	return false
}

func detectJSONSBOMStandard(data []byte) (SBOMStandard, string) {
	if std, ver := detectCycloneDXJSON(data); std != SBOMStandardUnknown {
		return std, ver
	}
	if std, ver := detectSPDXJSON(data); std != SBOMStandardUnknown {
		return std, ver
	}
	return SBOMStandardUnknown, ""
}

func detectCycloneDXJSON(data []byte) (SBOMStandard, string) {
	if !bytes.Contains(data, []byte(`"bomFormat"`)) {
		return SBOMStandardUnknown, ""
	}
	ver := extractJSONString(data, `"specVersion"`)
	return SBOMStandardCycloneDX, ver
}

func detectSPDXJSON(data []byte) (SBOMStandard, string) {
	ver := extractJSONString(data, `"spdxVersion"`)
	if ver == "" {
		return SBOMStandardUnknown, ""
	}
	return SBOMStandardSPDX, strings.TrimPrefix(ver, "SPDX-")
}

func extractJSONString(data []byte, key string) string {
	idx := bytes.Index(data, []byte(key))
	if idx == -1 {
		return ""
	}
	afterKey := data[idx+len(key):]
	colonIdx := bytes.IndexByte(afterKey, ':')
	if colonIdx == -1 {
		return ""
	}
	afterColon := bytes.TrimSpace(afterKey[colonIdx+1:])
	if len(afterColon) == 0 || afterColon[0] != '"' {
		return ""
	}
	afterColon = afterColon[1:]
	end := bytes.IndexByte(afterColon, '"')
	if end == -1 {
		return ""
	}
	return string(afterColon[:end])
}

func detectXMLSBOMStandard(data []byte) (SBOMStandard, string) {
	if bytes.Contains(data, []byte("cyclonedx")) {
		ver := extractCycloneDXXMLVersion(data)
		return SBOMStandardCycloneDX, ver
	}
	if bytes.Contains(data, []byte("SPDX")) {
		return SBOMStandardSPDX, extractSPDXXMLVersion(data)
	}
	return SBOMStandardUnknown, ""
}

func isRDF(data []byte) bool {
	return bytes.Contains(data, []byte("<rdf:RDF")) && bytes.Contains(data, []byte("spdx.org/rdf/terms"))
}

func detectRDFStandard(data []byte) (SBOMStandard, string) {
	if bytes.Contains(data, []byte("spdx.org/rdf/terms")) {
		ver := extractRDFVersion(data)
		return SBOMStandardSPDX, ver
	}
	return SBOMStandardUnknown, ""
}

func extractCycloneDXXMLVersion(data []byte) string {
	prefix := []byte(`xmlns="http://cyclonedx.org/schema/bom/`)
	idx := bytes.Index(data, prefix)
	if idx == -1 {
		return ""
	}
	rest := data[idx+len(prefix):]
	end := bytes.IndexByte(rest, '"')
	if end == -1 {
		return ""
	}
	return string(rest[:end])
}

func extractSPDXXMLVersion(data []byte) string {
	idx := bytes.Index(data, []byte(`spdxVersion="`))
	if idx == -1 {
		return ""
	}
	rest := data[idx+13:]
	end := bytes.IndexByte(rest, '"')
	if end == -1 {
		return ""
	}
	return strings.TrimPrefix(string(rest[:end]), "SPDX-")
}

func extractRDFVersion(data []byte) string {
	idx := bytes.Index(data, []byte(`spdx:specVersion`))
	if idx == -1 {
		return ""
	}
	rest := data[idx+16:]
	rest = bytes.TrimSpace(rest)
	if len(rest) == 0 {
		return ""
	}
	switch rest[0] {
	case '"':
		rest = rest[1:]
		end := bytes.IndexByte(rest, '"')
		if end == -1 {
			return ""
		}
		return strings.TrimPrefix(string(rest[:end]), "SPDX-")
	case '>':
		rest = rest[1:]
		end := bytes.IndexByte(rest, '<')
		if end == -1 {
			return ""
		}
		return strings.TrimPrefix(string(bytes.TrimSpace(rest[:end])), "SPDX-")
	}
	return ""
}

func detectTagValueSBOMStandard(data []byte) (SBOMStandard, string) {
	lines := bytes.Split(data, []byte("\n"))
	for _, line := range lines {
		if bytes.HasPrefix(line, []byte("SPDXVersion:")) {
			ver := strings.TrimSpace(string(bytes.TrimPrefix(line, []byte("SPDXVersion:"))))
			return SBOMStandardSPDX, strings.TrimPrefix(ver, "SPDX-")
		}
	}
	return SBOMStandardUnknown, ""
}
