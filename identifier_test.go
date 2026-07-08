package strangelove

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentifier_EmptyInput(t *testing.T) {
	id := NewIdentifier()
	_, err := id.Identify(bytes.NewReader(nil))
	require.ErrorIs(t, err, ErrEmptyInput)
}

func TestIdentifier_GarbageInput(t *testing.T) {
	id := NewIdentifier()
	_, err := id.Identify(bytes.NewReader([]byte("!@#$%^&*()\nnot an sbom\n")))
	require.ErrorIs(t, err, ErrUnknownFormat)
}

func TestIdentifier_PlainJSON(t *testing.T) {
	id := NewIdentifier()
	_, err := id.Identify(bytes.NewReader([]byte(`{"foo":"bar"}`)))
	require.ErrorIs(t, err, ErrUnknownFormat)
}

func TestIdentifier_PlainXML(t *testing.T) {
	id := NewIdentifier()
	_, err := id.Identify(bytes.NewReader([]byte(`<root><item/></root>`)))
	require.ErrorIs(t, err, ErrUnknownFormat)
}

func TestIdentifier_CycloneDX_JSON(t *testing.T) {
	id := NewIdentifier()
	data := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79","version":1}`)
	dr, err := id.Identify(bytes.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, SBOMStandardCycloneDX, dr.Format.SBOMStandard)
	assert.Equal(t, SerializationJSON, dr.Format.Serialization)
	assert.Equal(t, "1.6", dr.Format.SpecVersion)
}

func TestIdentifier_CycloneDX_XML(t *testing.T) {
	id := NewIdentifier()
	data := []byte(`<?xml version="1.0"?><bom serialNumber="urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79" version="1" xmlns="http://cyclonedx.org/schema/bom/1.6">`)
	dr, err := id.Identify(bytes.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, SBOMStandardCycloneDX, dr.Format.SBOMStandard)
	assert.Equal(t, SerializationXML, dr.Format.Serialization)
	assert.Equal(t, "1.6", dr.Format.SpecVersion)
}

func TestIdentifier_SPDX_JSON(t *testing.T) {
	id := NewIdentifier()
	data := []byte(`{"spdxVersion":"SPDX-2.2","SPDXID":"SPDXRef-DOCUMENT","name":"SPDX-Tools-v2.0"}`)
	dr, err := id.Identify(bytes.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, SBOMStandardSPDX, dr.Format.SBOMStandard)
	assert.Equal(t, SerializationJSON, dr.Format.Serialization)
	assert.Equal(t, "2.2", dr.Format.SpecVersion)
}

func TestIdentifier_SPDX_TagValue(t *testing.T) {
	id := NewIdentifier()
	data := []byte("SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\nSPDXID: SPDXRef-DOCUMENT\n")
	dr, err := id.Identify(bytes.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, SBOMStandardSPDX, dr.Format.SBOMStandard)
	assert.Equal(t, SerializationSPDXTagValue, dr.Format.Serialization)
	assert.Equal(t, "2.3", dr.Format.SpecVersion)
}

func TestIdentifier_WithPeekSize(t *testing.T) {
	id := NewIdentifier(WithPeekSize(128))
	data := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`)
	dr, err := id.Identify(bytes.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, SBOMStandardCycloneDX, dr.Format.SBOMStandard)
}

func TestIdentifier_ReaderPreservation(t *testing.T) {
	data := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`)
	r := bytes.NewReader(data)

	id := NewIdentifier()
	dr, err := id.Identify(r)
	require.NoError(t, err)
	assert.Equal(t, SBOMStandardCycloneDX, dr.Format.SBOMStandard)

	remaining, err := io.ReadAll(dr.Reader)
	require.NoError(t, err)
	assert.NotEmpty(t, remaining)
}

func TestIdentifier_SPDX_RDF(t *testing.T) {
	id := NewIdentifier()
	data := []byte(`<rdf:RDF xmlns:spdx="http://spdx.org/rdf/terms#" xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><spdx:SpdxDocument rdf:about=""><spdx:specVersion>SPDX-2.2</spdx:specVersion></spdx:SpdxDocument></rdf:RDF>`)
	dr, err := id.Identify(bytes.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, SBOMStandardSPDX, dr.Format.SBOMStandard)
	assert.Equal(t, SerializationRDF, dr.Format.Serialization)
	assert.Equal(t, "2.2", dr.Format.SpecVersion)
}

func TestIdentifier_LargeFixture(t *testing.T) {
	id := NewIdentifier()
	r := bytes.NewReader(sampleCycloneDXJSON())
	dr, err := id.Identify(r)
	require.NoError(t, err)
	assert.Equal(t, SBOMStandardCycloneDX, dr.Format.SBOMStandard)
	assert.Equal(t, SerializationJSON, dr.Format.Serialization)
	assert.Equal(t, "1.5", dr.Format.SpecVersion)

	remaining, err := io.ReadAll(dr.Reader)
	require.NoError(t, err)
	assert.NotEmpty(t, remaining)
}

func TestIdentifier_PlainJSON_FromFixture(t *testing.T) {
	f := openFixture(t, "testdata/not-sbom/plain.json")

	id := NewIdentifier()
	_, err := id.Identify(f)
	require.ErrorIs(t, err, ErrUnknownFormat)
}

func TestIdentifier_PlainXML_FromFixture(t *testing.T) {
	f := openFixture(t, "testdata/not-sbom/plain.xml")

	id := NewIdentifier()
	_, err := id.Identify(f)
	require.ErrorIs(t, err, ErrUnknownFormat)
}

func TestIdentifier_EmptyFile(t *testing.T) {
	f := openFixture(t, "testdata/empty.txt")

	id := NewIdentifier()
	_, err := id.Identify(f)
	require.ErrorIs(t, err, ErrEmptyInput)
}

func sampleCycloneDXJSON() []byte {
	var b bytes.Buffer
	b.WriteString(`{"bomFormat":"CycloneDX","specVersion":"1.5","serialNumber":"urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79","version":1,`)
	b.WriteString(`"components":[`)
	for i := 0; i < 200; i++ {
		if i > 0 {
			b.WriteString(`,`)
		}
		b.WriteString(`{"type":"library","name":"component-`)
		b.WriteByte(byte('A' + byte(i%26)))
		b.WriteString(`","version":"1.0.0"}`)
	}
	b.WriteString(`]}`)
	return b.Bytes()
}
