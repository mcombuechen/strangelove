package strangelove

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spdx/tools-golang/spdx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshaler_SPDX_JSON(t *testing.T) {
	data := `{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"test","documentNamespace":"https://example.com","creationInfo":{"created":"2024-01-15T10:30:00Z","creators":["Person: Test","Organization: Acme Corp","Tool: mytool-1.0"]}}`
	u := NewUnmarshaler()
	doc, err := u.Unmarshal(strings.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, SBOMStandardSPDX, doc.Format.SBOMStandard)
	assert.Equal(t, SerializationJSON, doc.Format.Serialization)
	assert.Equal(t, "2.3", doc.Format.SpecVersion)
	assert.Equal(t, time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC), doc.Meta.CreatedAt)

	require.Len(t, doc.Meta.Authors, 2)
	assert.Equal(t, AuthorPerson, doc.Meta.Authors[0].Type)
	assert.Equal(t, "Test", doc.Meta.Authors[0].Name)
	assert.Equal(t, AuthorOrganization, doc.Meta.Authors[1].Type)
	assert.Equal(t, "Acme Corp", doc.Meta.Authors[1].Name)

	require.Len(t, doc.Meta.Tools, 1)
	assert.Equal(t, ToolTypeTool, doc.Meta.Tools[0].Type)
	assert.Equal(t, "mytool-1.0", doc.Meta.Tools[0].Name)

	sbom := doc.SBOM()
	require.NotNil(t, sbom)
	spdxDoc, ok := sbom.(*spdx.Document)
	require.True(t, ok, "SBOM() should return *spdx.Document")
	assert.Equal(t, "test", spdxDoc.DocumentName)
}

func TestUnmarshaler_SPDX_TagValue(t *testing.T) {
	data := "SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\nSPDXID: SPDXRef-DOCUMENT\nDocumentName: test\nDocumentNamespace: https://example.com\nCreator: Person: Test\nCreator: Organization: Acme Corp\nCreator: Tool: mytool-1.0\nCreated: 2024-01-15T10:30:00Z\n"
	u := NewUnmarshaler()
	doc, err := u.Unmarshal(strings.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, SBOMStandardSPDX, doc.Format.SBOMStandard)
	assert.Equal(t, SerializationSPDXTagValue, doc.Format.Serialization)
	assert.Equal(t, "2.3", doc.Format.SpecVersion)
	assert.Equal(t, time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC), doc.Meta.CreatedAt)

	require.Len(t, doc.Meta.Authors, 2)
	assert.Equal(t, AuthorPerson, doc.Meta.Authors[0].Type)
	assert.Equal(t, "Test", doc.Meta.Authors[0].Name)
	assert.Equal(t, AuthorOrganization, doc.Meta.Authors[1].Type)
	assert.Equal(t, "Acme Corp", doc.Meta.Authors[1].Name)

	require.Len(t, doc.Meta.Tools, 1)
	assert.Equal(t, ToolTypeTool, doc.Meta.Tools[0].Type)
	assert.Equal(t, "mytool-1.0", doc.Meta.Tools[0].Name)

	sbom := doc.SBOM()
	require.NotNil(t, sbom)
	spdxDoc, ok := sbom.(*spdx.Document)
	require.True(t, ok)
	assert.Equal(t, "test", spdxDoc.DocumentName)
}

func TestUnmarshaler_SPDX_RDF(t *testing.T) {
	data := `<rdf:RDF xmlns:spdx="http://spdx.org/rdf/terms#" xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://spdx.org/spdxdocs/test#"><spdx:SpdxDocument rdf:about="http://spdx.org/spdxdocs/test#"><spdx:specVersion>SPDX-2.2</spdx:specVersion><spdx:creationInfo><spdx:created>2024-06-15T10:30:00Z</spdx:created><spdx:creator>Person: Test</spdx:creator></spdx:creationInfo><spdx:name>test</spdx:name><spdx:dataLicense>CC0-1.0</spdx:dataLicense></spdx:SpdxDocument></rdf:RDF>`
	u := NewUnmarshaler()
	doc, err := u.Unmarshal(strings.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, SBOMStandardSPDX, doc.Format.SBOMStandard)
	assert.Equal(t, SerializationRDF, doc.Format.Serialization)

	sbom := doc.SBOM()
	require.NotNil(t, sbom)
	spdxDoc, ok := sbom.(*spdx.Document)
	require.True(t, ok)
	assert.Equal(t, "test", spdxDoc.DocumentName)
}

func TestUnmarshaler_SPDX_BadTimestamp(t *testing.T) {
	data := `{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"test","documentNamespace":"https://example.com","creationInfo":{"created":"not-a-timestamp","creators":["Person: Test"]}}`
	u := NewUnmarshaler()
	_, err := u.Unmarshal(strings.NewReader(data))
	require.Error(t, err)
	assert.ErrorContains(t, err, "invalid Created timestamp")
}

func TestUnmarshaler_CycloneDX_JSON(t *testing.T) {
	data := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"timestamp":"2024-01-15T10:30:00Z","authors":[{"name":"Jane Doe","email":"jane@example.com"}]}}`
	u := NewUnmarshaler()
	doc, err := u.Unmarshal(strings.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, SBOMStandardCycloneDX, doc.Format.SBOMStandard)
	assert.Equal(t, SerializationJSON, doc.Format.Serialization)
	assert.Equal(t, "1.6", doc.Format.SpecVersion)
	assert.Equal(t, time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC), doc.Meta.CreatedAt)

	require.Len(t, doc.Meta.Authors, 1)
	assert.Equal(t, AuthorPerson, doc.Meta.Authors[0].Type)
	assert.Equal(t, "Jane Doe", doc.Meta.Authors[0].Name)
	assert.Equal(t, "jane@example.com", doc.Meta.Authors[0].Email)

	sbom := doc.SBOM()
	require.NotNil(t, sbom)
	_, ok := sbom.(*cdx.BOM)
	require.True(t, ok, "SBOM() should return *cdx.BOM")
}

func TestUnmarshaler_CycloneDX_XML(t *testing.T) {
	f := openFixture(t, "testdata/cyclonedx/valid-bom.xml")

	u := NewUnmarshaler()
	doc, err := u.Unmarshal(f)
	require.NoError(t, err)
	assert.Equal(t, SBOMStandardCycloneDX, doc.Format.SBOMStandard)
	assert.Equal(t, SerializationXML, doc.Format.Serialization)
	assert.Equal(t, "1.6", doc.Format.SpecVersion)
	assert.Equal(t, time.Date(2020, 4, 7, 7, 1, 0, 0, time.UTC), doc.Meta.CreatedAt)

	require.Len(t, doc.Meta.Authors, 1)
	assert.Equal(t, "Samantha Wright", doc.Meta.Authors[0].Name)
	assert.Equal(t, "samantha.wright@example.com", doc.Meta.Authors[0].Email)

	require.Len(t, doc.Meta.Tools, 2)
	assert.Equal(t, ToolTypeComponent, doc.Meta.Tools[0].Type)
	assert.Equal(t, "Awesome Tool", doc.Meta.Tools[0].Name)
	assert.Equal(t, "9.1.2", doc.Meta.Tools[0].Version)
	assert.Equal(t, ToolTypeService, doc.Meta.Tools[1].Type)
	assert.Equal(t, "Acme Signing Server", doc.Meta.Tools[1].Name)

	sbom := doc.SBOM()
	require.NotNil(t, sbom)
	_, ok := sbom.(*cdx.BOM)
	require.True(t, ok)
}

func TestUnmarshaler_CycloneDX_BadTimestamp(t *testing.T) {
	data := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"timestamp":"not-a-timestamp"}}`
	u := NewUnmarshaler()
	_, err := u.Unmarshal(strings.NewReader(data))
	require.Error(t, err)
	assert.ErrorContains(t, err, "invalid Timestamp")
}

func TestUnmarshaler_CycloneDX_JSON_Fixture(t *testing.T) {
	f := openFixture(t, "testdata/cyclonedx/valid-bom.json")

	u := NewUnmarshaler()
	doc, err := u.Unmarshal(f)
	require.NoError(t, err)
	assert.Equal(t, SBOMStandardCycloneDX, doc.Format.SBOMStandard)
	assert.Equal(t, SerializationJSON, doc.Format.Serialization)
	assert.NotZero(t, doc.Meta.CreatedAt)

	require.Len(t, doc.Meta.Authors, 1)
	assert.Equal(t, "Samantha Wright", doc.Meta.Authors[0].Name)
	assert.Equal(t, "samantha.wright@example.com", doc.Meta.Authors[0].Email)

	require.Len(t, doc.Meta.Tools, 2)

	sbom := doc.SBOM()
	require.NotNil(t, sbom)
	_, ok := sbom.(*cdx.BOM)
	require.True(t, ok)
}

func TestUnmarshaler_WithCustomIdentifier(t *testing.T) {
	id := NewIdentifier(WithPeekSize(128))
	u := NewUnmarshaler(WithIdentifier(id))

	data := `{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"test","documentNamespace":"https://example.com","creationInfo":{"created":"2024-01-15T10:30:00Z","creators":["Person: Test"]}}`
	doc, err := u.Unmarshal(strings.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, SBOMStandardSPDX, doc.Format.SBOMStandard)
}

func TestUnmarshaler_EmptyInput(t *testing.T) {
	u := NewUnmarshaler()
	_, err := u.Unmarshal(bytes.NewReader(nil))
	require.Error(t, err)
}

func TestUnmarshaler_UnknownFormat(t *testing.T) {
	u := NewUnmarshaler()
	_, err := u.Unmarshal(strings.NewReader("not an sbom"))
	require.Error(t, err)
}

func TestUnmarshaler_SPDX_JSON_Fixture_2_2(t *testing.T) {
	f := openFixture(t, "testdata/spdx/SPDXJSONExample-v2.2.spdx.json")

	u := NewUnmarshaler()
	doc, err := u.Unmarshal(f)
	require.NoError(t, err)
	assert.Equal(t, SBOMStandardSPDX, doc.Format.SBOMStandard)
	assert.Equal(t, SerializationJSON, doc.Format.Serialization)
	assert.Equal(t, "2.2", doc.Format.SpecVersion)
	assert.NotZero(t, doc.Meta.CreatedAt)

	assert.Len(t, doc.Meta.Authors, 2)
	assert.Len(t, doc.Meta.Tools, 1)
	assert.Equal(t, ToolTypeTool, doc.Meta.Tools[0].Type)
	assert.Equal(t, "LicenseFind-1.0", doc.Meta.Tools[0].Name)

	sbom := doc.SBOM()
	require.NotNil(t, sbom)
	_, ok := sbom.(*spdx.Document)
	require.True(t, ok)
}

func TestUnmarshaler_SPDX_TagValue_Fixture_2_2(t *testing.T) {
	f := openFixture(t, "testdata/spdx/SPDXTagExample-v2.2.spdx")

	u := NewUnmarshaler()
	doc, err := u.Unmarshal(f)
	require.NoError(t, err)
	assert.Equal(t, SBOMStandardSPDX, doc.Format.SBOMStandard)
	assert.Equal(t, SerializationSPDXTagValue, doc.Format.Serialization)
	assert.Equal(t, "2.2", doc.Format.SpecVersion)
	assert.NotZero(t, doc.Meta.CreatedAt)

	assert.Len(t, doc.Meta.Authors, 2)
	assert.Len(t, doc.Meta.Tools, 1)
	assert.Equal(t, ToolTypeTool, doc.Meta.Tools[0].Type)
	assert.Equal(t, "LicenseFind-1.0", doc.Meta.Tools[0].Name)

	sbom := doc.SBOM()
	require.NotNil(t, sbom)
	_, ok := sbom.(*spdx.Document)
	require.True(t, ok)
}

func TestUnmarshaler_SPDX_JSON_Fixture(t *testing.T) {
	f := openFixture(t, "testdata/spdx/SPDXJSONExample-v2.3.spdx.json")

	u := NewUnmarshaler()
	doc, err := u.Unmarshal(f)
	require.NoError(t, err)
	assert.Equal(t, SBOMStandardSPDX, doc.Format.SBOMStandard)
	assert.Equal(t, SerializationJSON, doc.Format.Serialization)
	assert.NotZero(t, doc.Meta.CreatedAt)

	assert.Len(t, doc.Meta.Authors, 2)
	assert.Len(t, doc.Meta.Tools, 1)
	assert.Equal(t, ToolTypeTool, doc.Meta.Tools[0].Type)
	assert.Equal(t, "LicenseFind-1.0", doc.Meta.Tools[0].Name)

	sbom := doc.SBOM()
	require.NotNil(t, sbom)
	_, ok := sbom.(*spdx.Document)
	require.True(t, ok)
}

func TestUnmarshaler_SPDX_TagValue_Fixture(t *testing.T) {
	f := openFixture(t, "testdata/spdx/SPDXTagExample-v2.3.spdx")

	u := NewUnmarshaler()
	doc, err := u.Unmarshal(f)
	require.NoError(t, err)
	assert.Equal(t, SBOMStandardSPDX, doc.Format.SBOMStandard)
	assert.Equal(t, SerializationSPDXTagValue, doc.Format.Serialization)
	assert.NotZero(t, doc.Meta.CreatedAt)

	assert.Len(t, doc.Meta.Authors, 2)
	assert.Len(t, doc.Meta.Tools, 1)
	assert.Equal(t, ToolTypeTool, doc.Meta.Tools[0].Type)
	assert.Equal(t, "LicenseFind-1.0", doc.Meta.Tools[0].Name)

	sbom := doc.SBOM()
	require.NotNil(t, sbom)
	_, ok := sbom.(*spdx.Document)
	require.True(t, ok)
}

func openFixture(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	return f
}
