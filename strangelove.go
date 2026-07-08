package strangelove

import "time"

// SBOMStandard identifies the SBOM specification standard.
type SBOMStandard int

const (
	SBOMStandardUnknown   SBOMStandard = iota
	SBOMStandardCycloneDX              // CycloneDX
	SBOMStandardSPDX                   // SPDX
)

func (s SBOMStandard) String() string {
	switch s {
	case SBOMStandardCycloneDX:
		return "CycloneDX"
	case SBOMStandardSPDX:
		return "SPDX"
	default:
		return "unknown"
	}
}

// Serialization identifies the serialization format of the SBOM document.
type Serialization int

const (
	SerializationUnknown      Serialization = iota
	SerializationJSON                       // JSON
	SerializationXML                        // XML
	SerializationSPDXTagValue               // SPDX Tag-Value
	SerializationRDF                        // RDF/XML (SPDX)
)

func (s Serialization) String() string {
	switch s {
	case SerializationJSON:
		return "JSON"
	case SerializationXML:
		return "XML"
	case SerializationSPDXTagValue:
		return "TagValue"
	case SerializationRDF:
		return "RDF"
	default:
		return "unknown"
	}
}

// SBOMFormat describes the complete format of an SBOM document.
type SBOMFormat struct {
	SBOMStandard  SBOMStandard
	Serialization Serialization
	SpecVersion   string
}

func (f SBOMFormat) String() string {
	return f.SBOMStandard.String() + "/" + f.Serialization.String() + " (v" + f.SpecVersion + ")"
}

// AuthorType distinguishes the kind of author or entity.
type AuthorType int

const (
	AuthorPerson       AuthorType = iota // a natural person
	AuthorOrganization                   // an organization
)

// Author represents a person or organization that contributed to or is
// associated with the SBOM or a component.
type Author struct {
	Type  AuthorType
	Name  string
	Email string
}

// ToolType distinguishes the origin of a tool entry.
type ToolType int

const (
	ToolTypeTool      ToolType = iota // a general tool
	ToolTypeComponent                 // a component used as a tool (CycloneDX)
	ToolTypeService                   // a service used as a tool (CycloneDX)
)

// Tool represents a tool used in the creation of the SBOM.
type Tool struct {
	Type    ToolType
	Name    string
	Version string
	Vendor  string
}

// ComponentType classifies the type of a software component.
type ComponentType int

const (
	ComponentTypeOther           ComponentType = iota // unrecognized or unspecified
	ComponentTypeApplication                          // an application
	ComponentTypeLibrary                              // a library
	ComponentTypeFramework                            // a framework
	ComponentTypeContainer                            // a container
	ComponentTypeOperatingSystem                      // an operating system
	ComponentTypeDevice                               // a hardware device
	ComponentTypeFirmware                             // firmware
	ComponentTypeFile                                 // a file
	ComponentTypeSource                               // source code (SPDX)
	ComponentTypeArchive                              // an archive (SPDX)
	ComponentTypeInstall                              // an installer (SPDX)
)

// Hash represents a cryptographic checksum of a component.
type Hash struct {
	Algorithm string // e.g. "SHA-256", "SHA1", "MD5"
	Value     string
}

// Entity represents a named organization or person with contact information.
type Entity struct {
	Name  string
	Email string
	URL   []string
}

// Component represents a software component or package extracted from an SBOM.
type Component struct {
	ID      string // bom-ref (CycloneDX) or SPDXRef-* (SPDX)
	Name    string
	Version string
	Type    ComponentType

	Supplier  *Entity
	Authors   []Author
	Publisher string

	Hashes []Hash

	PackageURL       string // package URL (purl)
	CPE              string // Common Platform Enumeration
	FileName         string // SPDX PackageFileName
	DownloadLocation string // SPDX PackageDownloadLocation

	Description string
	Copyright   string
	SourceInfo  string // SPDX PackageSourceInfo
}

// Meta contains SBOM-level metadata.
type Meta struct {
	CreatedAt time.Time
	Authors   []Author
	Tools     []Tool
}

// Document is the result of unmarshaling an SBOM. It contains the detected
// format, parsed metadata, and a unified component inventory.
type Document struct {
	Format     SBOMFormat
	Meta       Meta
	Components []Component
	doc        any
}

// SBOM returns the underlying library-specific parsed document. Use type
// assertion to access standard-specific fields:
//
//	if cdxDoc, ok := doc.SBOM().(*cyclonedx.BOM); ok { ... }
func (d *Document) SBOM() any {
	return d.doc
}
