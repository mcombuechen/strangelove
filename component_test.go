package strangelove

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComponents_SPDX_JSON_Inline(t *testing.T) {
	data := `{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"test","documentNamespace":"https://example.com","creationInfo":{"created":"2024-01-15T10:30:00Z","creators":["Person: Test"]},"packages":[{"SPDXID":"SPDXRef-Pkg1","name":"test-pkg","versionInfo":"1.0.0","supplier":"Person: Jane Doe (jane@example.com)","originator":"Organization: Acme Corp (acme@example.com)","downloadLocation":"https://example.com/pkg.tar.gz","packageFileName":"pkg-1.0.0.tar.gz","primaryPackagePurpose":"LIBRARY","checksums":[{"algorithm":"SHA256","checksumValue":"abc123"}],"copyrightText":"Copyright 2024","description":"A test package","sourceInfo":"Built from source"}]}`
	u := NewUnmarshaler()
	doc, err := u.Unmarshal(strings.NewReader(data))
	require.NoError(t, err)
	require.Len(t, doc.Components, 1)

	c := doc.Components[0]
	assert.Equal(t, "SPDXRef-Pkg1", c.ID)
	assert.Equal(t, "test-pkg", c.Name)
	assert.Equal(t, "1.0.0", c.Version)
	assert.Equal(t, ComponentTypeLibrary, c.Type)

	require.NotNil(t, c.Supplier)
	assert.Equal(t, "Jane Doe", c.Supplier.Name)
	assert.Equal(t, "jane@example.com", c.Supplier.Email)

	require.Len(t, c.Authors, 1)
	assert.Equal(t, AuthorOrganization, c.Authors[0].Type)
	assert.Equal(t, "Acme Corp", c.Authors[0].Name)
	assert.Equal(t, "acme@example.com", c.Authors[0].Email)

	assert.Equal(t, "https://example.com/pkg.tar.gz", c.DownloadLocation)
	assert.Equal(t, "pkg-1.0.0.tar.gz", c.FileName)
	assert.Equal(t, "Copyright 2024", c.Copyright)
	assert.Equal(t, "A test package", c.Description)
	assert.Equal(t, "Built from source", c.SourceInfo)

	require.Len(t, c.Hashes, 1)
	assert.Equal(t, "SHA256", c.Hashes[0].Algorithm)
	assert.Equal(t, "abc123", c.Hashes[0].Value)
}

func TestComponents_SPDX_JSON_NOASSERTION(t *testing.T) {
	data := `{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"test","documentNamespace":"https://example.com","creationInfo":{"created":"2024-01-15T10:30:00Z","creators":["Person: Test"]},"packages":[{"SPDXID":"SPDXRef-Pkg1","name":"pkg1","versionInfo":"1.0","supplier":"NOASSERTION","originator":"NOASSERTION","downloadLocation":"NOASSERTION","copyrightText":"NOASSERTION"}]}`
	u := NewUnmarshaler()
	doc, err := u.Unmarshal(strings.NewReader(data))
	require.NoError(t, err)
	require.Len(t, doc.Components, 1)

	c := doc.Components[0]
	assert.Nil(t, c.Supplier)
	assert.Empty(t, c.Authors)
	assert.Empty(t, c.DownloadLocation)
	assert.Empty(t, c.Copyright)
}

func TestComponents_SPDX_EmptyPackages(t *testing.T) {
	data := `{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"test","documentNamespace":"https://example.com","creationInfo":{"created":"2024-01-15T10:30:00Z","creators":["Person: Test"]}}`
	u := NewUnmarshaler()
	doc, err := u.Unmarshal(strings.NewReader(data))
	require.NoError(t, err)
	assert.Empty(t, doc.Components)
}

func TestComponents_CycloneDX_JSON_Inline(t *testing.T) {
	data := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"bom-ref":"pkg:test/test-pkg@1.0.0","type":"library","name":"test-pkg","version":"1.0.0","supplier":{"name":"Acme Corp","url":["https://acme.com"],"contact":[{"name":"Jane","email":"jane@acme.com"}]},"authors":[{"name":"Alice","email":"alice@acme.com"},{"name":"Bob","email":"bob@acme.com"}],"publisher":"Acme Publishing","hashes":[{"alg":"SHA-256","content":"abc123"}],"purl":"pkg:test/test-pkg@1.0.0","cpe":"cpe:2.3:a:acme:test-pkg:1.0.0:*:*:*:*:*:*:*","description":"A test component","copyright":"Copyright 2024 Acme Corp"}]}`
	u := NewUnmarshaler()
	doc, err := u.Unmarshal(strings.NewReader(data))
	require.NoError(t, err)
	require.Len(t, doc.Components, 1)

	c := doc.Components[0]
	assert.Equal(t, "pkg:test/test-pkg@1.0.0", c.ID)
	assert.Equal(t, "test-pkg", c.Name)
	assert.Equal(t, "1.0.0", c.Version)
	assert.Equal(t, ComponentTypeLibrary, c.Type)

	require.NotNil(t, c.Supplier)
	assert.Equal(t, "Acme Corp", c.Supplier.Name)
	assert.Equal(t, "jane@acme.com", c.Supplier.Email)
	assert.Equal(t, []string{"https://acme.com"}, c.Supplier.URL)

	require.Len(t, c.Authors, 2)
	assert.Equal(t, "Alice", c.Authors[0].Name)
	assert.Equal(t, "alice@acme.com", c.Authors[0].Email)
	assert.Equal(t, "Bob", c.Authors[1].Name)
	assert.Equal(t, "bob@acme.com", c.Authors[1].Email)

	assert.Equal(t, "Acme Publishing", c.Publisher)
	assert.Equal(t, "pkg:test/test-pkg@1.0.0", c.PackageURL)
	assert.Equal(t, "cpe:2.3:a:acme:test-pkg:1.0.0:*:*:*:*:*:*:*", c.CPE)
	assert.Equal(t, "A test component", c.Description)
	assert.Equal(t, "Copyright 2024 Acme Corp", c.Copyright)

	require.Len(t, c.Hashes, 1)
	assert.Equal(t, "SHA-256", c.Hashes[0].Algorithm)
	assert.Equal(t, "abc123", c.Hashes[0].Value)
}

func TestComponents_CycloneDX_Nested_Flatten(t *testing.T) {
	data := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","name":"parent","version":"1.0","components":[{"type":"library","name":"child","version":"1.1","components":[{"type":"library","name":"grandchild","version":"1.2"}]}]}]}`
	u := NewUnmarshaler()
	doc, err := u.Unmarshal(strings.NewReader(data))
	require.NoError(t, err)
	require.Len(t, doc.Components, 3)

	assert.Equal(t, "parent", doc.Components[0].Name)
	assert.Equal(t, "child", doc.Components[1].Name)
	assert.Equal(t, "grandchild", doc.Components[2].Name)
}

func TestComponents_CycloneDX_EmptyComponents(t *testing.T) {
	data := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`
	u := NewUnmarshaler()
	doc, err := u.Unmarshal(strings.NewReader(data))
	require.NoError(t, err)
	assert.Empty(t, doc.Components)
}

func TestComponents_Entity_Parsing(t *testing.T) {
	t.Run("person with email", func(t *testing.T) {
		e := parseSPDXEntity("Person", "Jane Doe (jane@example.com)")
		require.NotNil(t, e)
		assert.Equal(t, "Jane Doe", e.Name)
		assert.Equal(t, "jane@example.com", e.Email)
	})

	t.Run("organization with email", func(t *testing.T) {
		e := parseSPDXEntity("Organization", "Acme Corp (acme@example.com)")
		require.NotNil(t, e)
		assert.Equal(t, "Acme Corp", e.Name)
		assert.Equal(t, "acme@example.com", e.Email)
	})

	t.Run("name with empty email", func(t *testing.T) {
		e := parseSPDXEntity("Person", "Jane Doe ()")
		require.NotNil(t, e)
		assert.Equal(t, "Jane Doe", e.Name)
		assert.Empty(t, e.Email)
	})

	t.Run("name only", func(t *testing.T) {
		e := parseSPDXEntity("Person", "Jane Doe")
		require.NotNil(t, e)
		assert.Equal(t, "Jane Doe", e.Name)
		assert.Empty(t, e.Email)
	})

	t.Run("NOASSERTION", func(t *testing.T) {
		e := parseSPDXEntity("", "NOASSERTION")
		assert.Nil(t, e)
	})

	t.Run("empty string", func(t *testing.T) {
		e := parseSPDXEntity("", "")
		assert.Nil(t, e)
	})
}

func TestComponents_ComponentType_SPDX(t *testing.T) {
	assert.Equal(t, ComponentTypeApplication, componentTypeFromSPDX("APPLICATION"))
	assert.Equal(t, ComponentTypeLibrary, componentTypeFromSPDX("LIBRARY"))
	assert.Equal(t, ComponentTypeFramework, componentTypeFromSPDX("FRAMEWORK"))
	assert.Equal(t, ComponentTypeContainer, componentTypeFromSPDX("CONTAINER"))
	assert.Equal(t, ComponentTypeOperatingSystem, componentTypeFromSPDX("OPERATING-SYSTEM"))
	assert.Equal(t, ComponentTypeDevice, componentTypeFromSPDX("DEVICE"))
	assert.Equal(t, ComponentTypeFirmware, componentTypeFromSPDX("FIRMWARE"))
	assert.Equal(t, ComponentTypeFile, componentTypeFromSPDX("FILE"))
	assert.Equal(t, ComponentTypeSource, componentTypeFromSPDX("SOURCE"))
	assert.Equal(t, ComponentTypeArchive, componentTypeFromSPDX("ARCHIVE"))
	assert.Equal(t, ComponentTypeInstall, componentTypeFromSPDX("INSTALL"))
	assert.Equal(t, ComponentTypeOther, componentTypeFromSPDX(""))
	assert.Equal(t, ComponentTypeOther, componentTypeFromSPDX("UNKNOWN"))
}

func TestComponents_SPDX_JSON_Fixture_2_2(t *testing.T) {
	f, err := os.Open("testdata/spdx/SPDXJSONExample-v2.2.spdx.json")
	require.NoError(t, err)
	defer f.Close()

	u := NewUnmarshaler()
	doc, err := u.Unmarshal(f)
	require.NoError(t, err)
	require.Len(t, doc.Components, 4)

	var glibc Component
	for _, c := range doc.Components {
		if c.Name == "glibc" {
			glibc = c
			break
		}
	}
	require.NotNil(t, glibc, "glibc package not found")
	assert.Equal(t, "SPDXRef-Package", glibc.ID)
	assert.Equal(t, "2.11.1", glibc.Version)
	assert.Equal(t, ComponentTypeOther, glibc.Type)

	require.NotNil(t, glibc.Supplier)
	assert.Equal(t, "Jane Doe", glibc.Supplier.Name)
	assert.Equal(t, "jane.doe@example.com", glibc.Supplier.Email)

	assert.Equal(t, "http://ftp.gnu.org/gnu/glibc/glibc-ports-2.15.tar.gz", glibc.DownloadLocation)
	assert.Equal(t, "glibc-2.11.1.tar.gz", glibc.FileName)
	assert.Equal(t, "Copyright 2008-2010 John Smith", glibc.Copyright)
	assert.Contains(t, glibc.Description, "GNU C Library")
	assert.Contains(t, glibc.SourceInfo, "glibc-2_11-branch")
	require.Len(t, glibc.Hashes, 3)
}

func TestComponents_SPDX_TagValue_Fixture_2_2(t *testing.T) {
	f, err := os.Open("testdata/spdx/SPDXTagExample-v2.2.spdx")
	require.NoError(t, err)
	defer f.Close()

	u := NewUnmarshaler()
	doc, err := u.Unmarshal(f)
	require.NoError(t, err)
	require.Len(t, doc.Components, 4)

	var glibc Component
	for _, c := range doc.Components {
		if c.Name == "glibc" {
			glibc = c
			break
		}
	}
	require.NotNil(t, glibc, "glibc package not found")
	assert.Equal(t, "SPDXRef-Package", glibc.ID)
	assert.Equal(t, "2.11.1", glibc.Version)
	assert.Equal(t, "Jane Doe", glibc.Supplier.Name)
	assert.Equal(t, "jane.doe@example.com", glibc.Supplier.Email)
	assert.True(t, len(glibc.Hashes) > 0)
}

func TestComponents_SPDX_RDF_Fixture(t *testing.T) {
	f, err := os.Open("testdata/spdx/SPDXRdfExample-v2.2.spdx.rdf")
	require.NoError(t, err)
	defer f.Close()

	u := NewUnmarshaler()
	doc, err := u.Unmarshal(f)
	require.NoError(t, err)

	assert.Equal(t, SBOMStandardSPDX, doc.Format.SBOMStandard)
	assert.Equal(t, SerializationRDF, doc.Format.Serialization)

	assert.NotEmpty(t, doc.Components)

	var glibc Component
	for _, c := range doc.Components {
		if c.Name == "glibc" {
			glibc = c
			break
		}
	}
	require.NotNil(t, glibc, "glibc package not found")
	assert.Equal(t, "SPDXRef-Package", glibc.ID)
	assert.Equal(t, "2.11.1", glibc.Version)
	assert.Equal(t, "Jane Doe", glibc.Supplier.Name)
	assert.Equal(t, "jane.doe@example.com", glibc.Supplier.Email)
	assert.NotEmpty(t, glibc.DownloadLocation)
}

func TestComponents_SPDX_JSON_Fixture(t *testing.T) {
	f, err := os.Open("testdata/spdx/SPDXJSONExample-v2.3.spdx.json")
	require.NoError(t, err)
	defer f.Close()

	u := NewUnmarshaler()
	doc, err := u.Unmarshal(f)
	require.NoError(t, err)
	require.Len(t, doc.Components, 5)

	var glibc Component
	for _, c := range doc.Components {
		if c.Name == "glibc" {
			glibc = c
			break
		}
	}
	require.NotNil(t, glibc, "glibc package not found")
	assert.Equal(t, "SPDXRef-Package", glibc.ID)
	assert.Equal(t, "2.11.1", glibc.Version)
	assert.Equal(t, ComponentTypeOther, glibc.Type) // no primaryPackagePurpose in fixture

	require.NotNil(t, glibc.Supplier)
	assert.Equal(t, "Jane Doe", glibc.Supplier.Name)
	assert.Equal(t, "jane.doe@example.com", glibc.Supplier.Email)

	require.Len(t, glibc.Authors, 1)
	assert.Equal(t, AuthorOrganization, glibc.Authors[0].Type)
	assert.Equal(t, "ExampleCodeInspect", glibc.Authors[0].Name)
	assert.Equal(t, "contact@example.com", glibc.Authors[0].Email)

	assert.Equal(t, "http://ftp.gnu.org/gnu/glibc/glibc-ports-2.15.tar.gz", glibc.DownloadLocation)
	assert.Equal(t, "glibc-2.11.1.tar.gz", glibc.FileName)
	assert.Equal(t, "Copyright 2008-2010 John Smith", glibc.Copyright)
	assert.Contains(t, glibc.Description, "GNU C Library")
	assert.Contains(t, glibc.SourceInfo, "glibc-2_11-branch")

	require.Len(t, glibc.Hashes, 3)

	var centos Component
	for _, c := range doc.Components {
		if c.Name == "centos" {
			centos = c
			break
		}
	}
	require.NotNil(t, centos, "centos package not found")
	assert.Equal(t, "SPDXRef-CentOS-7", centos.ID)
	assert.Equal(t, ComponentTypeContainer, centos.Type)
	assert.Nil(t, centos.Supplier)
	assert.Empty(t, centos.DownloadLocation)
}

func TestComponents_SPDX_TagValue_Fixture(t *testing.T) {
	f, err := os.Open("testdata/spdx/SPDXTagExample-v2.3.spdx")
	require.NoError(t, err)
	defer f.Close()

	u := NewUnmarshaler()
	doc, err := u.Unmarshal(f)
	require.NoError(t, err)
	require.Len(t, doc.Components, 5)

	var glibc Component
	for _, c := range doc.Components {
		if c.Name == "glibc" {
			glibc = c
			break
		}
	}
	require.NotNil(t, glibc, "glibc package not found")
	assert.Equal(t, "SPDXRef-Package", glibc.ID)
	assert.Equal(t, "2.11.1", glibc.Version)
	assert.Equal(t, "Jane Doe", glibc.Supplier.Name)
	assert.Equal(t, "jane.doe@example.com", glibc.Supplier.Email)
	assert.Len(t, glibc.Authors, 1)
	assert.Equal(t, "ExampleCodeInspect", glibc.Authors[0].Name)
	assert.Equal(t, ComponentTypeContainer, doc.Components[0].Type) // centos is first in tag-value
	assert.True(t, len(glibc.Hashes) > 0)
}

func TestComponents_CycloneDX_JSON_Fixture(t *testing.T) {
	f, err := os.Open("testdata/cyclonedx/valid-bom.json")
	require.NoError(t, err)
	defer f.Close()

	u := NewUnmarshaler()
	doc, err := u.Unmarshal(f)
	require.NoError(t, err)
	require.Len(t, doc.Components, 2)

	tomcat := doc.Components[0]
	assert.Equal(t, "pkg:npm/acme/component@1.0.0", tomcat.ID)
	assert.Equal(t, "tomcat-catalina", tomcat.Name)
	assert.Equal(t, "9.0.14", tomcat.Version)
	assert.Equal(t, ComponentTypeLibrary, tomcat.Type)

	assert.Nil(t, tomcat.Supplier)
	assert.Equal(t, "Acme Inc", tomcat.Publisher)
	assert.Equal(t, "pkg:npm/acme/component@1.0.0", tomcat.PackageURL)
	assert.Len(t, tomcat.Hashes, 4)

	mylib := doc.Components[1]
	assert.Equal(t, "mylibrary", mylib.Name)
	assert.Equal(t, "1.0.0", mylib.Version)
	assert.Equal(t, ComponentTypeLibrary, mylib.Type)
	assert.Empty(t, mylib.ID) // no bom-ref

	require.NotNil(t, mylib.Supplier)
	assert.Equal(t, "Example, Inc.", mylib.Supplier.Name)
	assert.Equal(t, "support@example.com", mylib.Supplier.Email)
	require.Len(t, mylib.Supplier.URL, 2)
	assert.Equal(t, "https://example.com", mylib.Supplier.URL[0])
}

func TestComponents_CycloneDX_XML_Fixture(t *testing.T) {
	f, err := os.Open("testdata/cyclonedx/valid-bom.xml")
	require.NoError(t, err)
	defer f.Close()

	u := NewUnmarshaler()
	doc, err := u.Unmarshal(f)
	require.NoError(t, err)
	require.Len(t, doc.Components, 3)

	assert.Equal(t, "tomcat-catalina", doc.Components[0].Name)
	assert.Equal(t, "mylibrary", doc.Components[1].Name)
	assert.Equal(t, "myframework", doc.Components[2].Name)
	assert.Equal(t, ComponentTypeFramework, doc.Components[2].Type)

	require.NotNil(t, doc.Components[1].Supplier)
	assert.Equal(t, "Example Inc.", doc.Components[1].Supplier.Name)
	assert.Len(t, doc.Components[0].Hashes, 4)
}
