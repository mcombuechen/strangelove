package strangelove

import (
	"fmt"
	"io"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func parseCycloneDX(f SBOMFormat, r io.Reader) (*Document, error) {
	var bomFormat cdx.BOMFileFormat

	switch f.Serialization {
	case SerializationJSON:
		bomFormat = cdx.BOMFileFormatJSON
	case SerializationXML:
		bomFormat = cdx.BOMFileFormatXML
	default:
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedFormat, f.Serialization)
	}

	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(r, bomFormat)
	if err := decoder.Decode(bom); err != nil {
		return nil, err
	}

	meta, err := metaFromCycloneDX(bom)
	if err != nil {
		return nil, fmt.Errorf("metadata: %w", err)
	}

	components, err := componentsFromCycloneDX(bom)
	if err != nil {
		return nil, fmt.Errorf("components: %w", err)
	}

	graph := newDependencyGraph(components)

	if bom.Dependencies != nil {
		for _, dep := range *bom.Dependencies {
			if dep.Dependencies == nil {
				continue
			}
			for _, target := range *dep.Dependencies {
				graph.addEdge(dep.Ref, target)
			}
		}
	}

	root := ""
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		root = bom.Metadata.Component.BOMRef
	}
	graph.ensureRoot(root)

	return &Document{Format: f, Meta: meta, Components: components, Graph: graph, doc: bom}, nil
}

func metaFromCycloneDX(bom *cdx.BOM) (Meta, error) {
	var meta Meta

	if bom.Metadata != nil {
		if bom.Metadata.Timestamp != "" {
			created, err := time.Parse(time.RFC3339, bom.Metadata.Timestamp)
			if err != nil {
				return Meta{}, fmt.Errorf("invalid Timestamp %q: %w", bom.Metadata.Timestamp, err)
			}
			meta.CreatedAt = created
		}

		if bom.Metadata.Authors != nil {
			for _, a := range *bom.Metadata.Authors {
				meta.Authors = append(meta.Authors, Author{
					Type:  AuthorPerson,
					Name:  a.Name,
					Email: a.Email,
				})
			}
		}

		if bom.Metadata.Tools != nil {
			if bom.Metadata.Tools.Tools != nil {
				for _, t := range *bom.Metadata.Tools.Tools {
					meta.Tools = append(meta.Tools, Tool{
						Type:    ToolTypeTool,
						Name:    t.Name,
						Version: t.Version,
						Vendor:  t.Vendor,
					})
				}
			}
			if bom.Metadata.Tools.Components != nil {
				for _, c := range *bom.Metadata.Tools.Components {
					meta.Tools = append(meta.Tools, Tool{
						Type:    ToolTypeComponent,
						Name:    c.Name,
						Version: c.Version,
						Vendor:  c.Group,
					})
				}
			}
			if bom.Metadata.Tools.Services != nil {
				for _, s := range *bom.Metadata.Tools.Services {
					meta.Tools = append(meta.Tools, Tool{
						Type:    ToolTypeService,
						Name:    s.Name,
						Version: s.Version,
					})
				}
			}
		}
	}

	return meta, nil
}

func componentTypeFromCDX(ct cdx.ComponentType) ComponentType {
	switch ct {
	case cdx.ComponentTypeApplication:
		return ComponentTypeApplication
	case cdx.ComponentTypeLibrary:
		return ComponentTypeLibrary
	case cdx.ComponentTypeFramework:
		return ComponentTypeFramework
	case cdx.ComponentTypeContainer:
		return ComponentTypeContainer
	case cdx.ComponentTypeOS:
		return ComponentTypeOperatingSystem
	case cdx.ComponentTypeDevice:
		return ComponentTypeDevice
	case cdx.ComponentTypeFirmware:
		return ComponentTypeFirmware
	case cdx.ComponentTypeFile:
		return ComponentTypeFile
	case cdx.ComponentTypeData:
		return ComponentTypeOther
	case cdx.ComponentTypeCryptographicAsset:
		return ComponentTypeOther
	case cdx.ComponentTypeDeviceDriver:
		return ComponentTypeOther
	case cdx.ComponentTypeMachineLearningModel:
		return ComponentTypeOther
	case cdx.ComponentTypePlatform:
		return ComponentTypeOther
	default:
		return ComponentTypeOther
	}
}

func flattenCDXComponents(comps *[]cdx.Component) []Component {
	if comps == nil {
		return nil
	}
	var result []Component
	for _, c := range *comps {
		result = append(result, componentFromCDX(c))
		if c.Components != nil {
			result = append(result, flattenCDXComponents(c.Components)...)
		}
	}
	return result
}

func componentFromCDX(c cdx.Component) Component {
	out := Component{
		ID:      c.BOMRef,
		Name:    c.Name,
		Version: c.Version,
		Type:    componentTypeFromCDX(c.Type),
		Hashes:  make([]Hash, 0),
	}

	if c.Supplier != nil && c.Supplier.Name != "" {
		ent := &Entity{Name: c.Supplier.Name}
		if c.Supplier.URL != nil {
			ent.URL = make([]string, len(*c.Supplier.URL))
			copy(ent.URL, *c.Supplier.URL)
		}
		if c.Supplier.Contact != nil && len(*c.Supplier.Contact) > 0 {
			ent.Email = (*c.Supplier.Contact)[0].Email
		}
		out.Supplier = ent
	}

	if c.Authors != nil {
		for _, a := range *c.Authors {
			out.Authors = append(out.Authors, Author{
				Type:  AuthorPerson,
				Name:  a.Name,
				Email: a.Email,
			})
		}
	}

	out.Publisher = c.Publisher
	out.PackageURL = c.PackageURL
	out.CPE = c.CPE
	out.Description = c.Description
	out.Copyright = strings.TrimSpace(c.Copyright)

	if c.Hashes != nil {
		for _, h := range *c.Hashes {
			out.Hashes = append(out.Hashes, Hash{
				Algorithm: string(h.Algorithm),
				Value:     h.Value,
			})
		}
	}

	return out
}

func componentsFromCycloneDX(bom *cdx.BOM) ([]Component, error) {
	return flattenCDXComponents(bom.Components), nil
}
