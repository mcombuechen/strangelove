package strangelove

import (
	"fmt"
	"io"
	"strings"
	"time"

	spdxJSON "github.com/spdx/tools-golang/json"
	spdxRDF "github.com/spdx/tools-golang/rdf"
	"github.com/spdx/tools-golang/spdx"
	spdxTagValue "github.com/spdx/tools-golang/tagvalue"
)

func parseSPDX(f SBOMFormat, r io.Reader) (*Document, error) {
	var doc *spdx.Document
	var err error

	switch f.Serialization {
	case SerializationJSON:
		doc, err = spdxJSON.Read(r)
	case SerializationSPDXTagValue:
		doc, err = spdxTagValue.Read(r)
	case SerializationRDF:
		doc, err = spdxRDF.Read(r)
	default:
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedFormat, f.Serialization)
	}
	if err != nil {
		return nil, err
	}

	meta, err := metaFromSPDX(doc)
	if err != nil {
		return nil, fmt.Errorf("metadata: %w", err)
	}

	components, err := componentsFromSPDX(doc)
	if err != nil {
		return nil, fmt.Errorf("components: %w", err)
	}

	return &Document{Format: f, Meta: meta, Components: components, doc: doc}, nil
}

func metaFromSPDX(doc *spdx.Document) (Meta, error) {
	var meta Meta

	if doc.CreationInfo != nil {
		if doc.CreationInfo.Created != "" {
			created, err := time.Parse(time.RFC3339, doc.CreationInfo.Created)
			if err != nil {
				return Meta{}, fmt.Errorf("invalid Created timestamp %q: %w", doc.CreationInfo.Created, err)
			}
			meta.CreatedAt = created
		}

		for _, c := range doc.CreationInfo.Creators {
			switch c.CreatorType {
			case "Person":
				meta.Authors = append(meta.Authors, Author{Type: AuthorPerson, Name: c.Creator})
			case "Organization":
				meta.Authors = append(meta.Authors, Author{Type: AuthorOrganization, Name: c.Creator})
			case "Tool":
				meta.Tools = append(meta.Tools, Tool{Type: ToolTypeTool, Name: c.Creator})
			}
		}
	}

	return meta, nil
}

func extractNameEmail(s string) (name, email string) {
	if idx := strings.Index(s, " ("); idx > 0 && strings.HasSuffix(s, ")") {
		name = s[:idx]
		if inner := s[idx+2 : len(s)-1]; inner != "" {
			email = inner
		}
		return name, email
	}
	return s, ""
}

func parseSPDXEntity(entityType, entityStr string) *Entity {
	if entityStr == "" || entityStr == "NOASSERTION" {
		return nil
	}
	ent := &Entity{}
	name, email := extractNameEmail(entityStr)
	ent.Name = name
	ent.Email = email
	return ent
}

func componentTypeFromSPDX(purpose string) ComponentType {
	switch strings.ToUpper(purpose) {
	case "APPLICATION":
		return ComponentTypeApplication
	case "LIBRARY":
		return ComponentTypeLibrary
	case "FRAMEWORK":
		return ComponentTypeFramework
	case "CONTAINER":
		return ComponentTypeContainer
	case "OPERATING-SYSTEM":
		return ComponentTypeOperatingSystem
	case "DEVICE":
		return ComponentTypeDevice
	case "FIRMWARE":
		return ComponentTypeFirmware
	case "FILE":
		return ComponentTypeFile
	case "SOURCE":
		return ComponentTypeSource
	case "ARCHIVE":
		return ComponentTypeArchive
	case "INSTALL":
		return ComponentTypeInstall
	default:
		return ComponentTypeOther
	}
}

func componentsFromSPDX(doc *spdx.Document) ([]Component, error) {
	var comps []Component
	for _, pkg := range doc.Packages {
		if pkg.IsUnpackaged {
			continue
		}

		c := Component{
			ID:      "SPDXRef-" + string(pkg.PackageSPDXIdentifier),
			Name:    pkg.PackageName,
			Version: pkg.PackageVersion,
			Type:    componentTypeFromSPDX(pkg.PrimaryPackagePurpose),
			Hashes:  make([]Hash, 0),
		}

		if pkg.PackageSupplier != nil {
			c.Supplier = parseSPDXEntity(pkg.PackageSupplier.SupplierType, pkg.PackageSupplier.Supplier)
		}

		if pkg.PackageOriginator != nil && pkg.PackageOriginator.Originator != "" && pkg.PackageOriginator.Originator != "NOASSERTION" {
			name, email := extractNameEmail(pkg.PackageOriginator.Originator)
			var at AuthorType
			switch pkg.PackageOriginator.OriginatorType {
			case "Person":
				at = AuthorPerson
			case "Organization":
				at = AuthorOrganization
			}
			c.Authors = append(c.Authors, Author{Type: at, Name: name, Email: email})
		}

		if pkg.PackageDownloadLocation != "" && pkg.PackageDownloadLocation != "NOASSERTION" {
			c.DownloadLocation = pkg.PackageDownloadLocation
		}

		c.FileName = pkg.PackageFileName

		if pkg.PackageDescription != "" {
			c.Description = pkg.PackageDescription
		}

		if pkg.PackageSourceInfo != "" {
			c.SourceInfo = pkg.PackageSourceInfo
		}

		if pkg.PackageCopyrightText != "" && pkg.PackageCopyrightText != "NOASSERTION" {
			c.Copyright = pkg.PackageCopyrightText
		}

		for _, chk := range pkg.PackageChecksums {
			c.Hashes = append(c.Hashes, Hash{
				Algorithm: string(chk.Algorithm),
				Value:     chk.Value,
			})
		}

		comps = append(comps, c)
	}
	return comps, nil
}
