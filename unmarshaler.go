package strangelove

import (
	"fmt"
	"io"
)

// Unmarshaler parses SBOM documents from any io.Reader. It uses an internal
// Identifier to auto-detect the format before parsing.
type Unmarshaler struct {
	identifier *Identifier
}

type unmarshalerOption func(*Unmarshaler)

// WithIdentifier sets a custom Identifier for format detection. Use this to
// configure peek size or other identification behaviour.
func WithIdentifier(id *Identifier) unmarshalerOption {
	return func(u *Unmarshaler) {
		u.identifier = id
	}
}

// Unmarshal identifies and parses an SBOM document from r using a default
// Unmarshaler. It is a convenience wrapper around NewUnmarshaler().Unmarshal.
func Unmarshal(r io.Reader) (*Document, error) {
	return NewUnmarshaler().Unmarshal(r)
}

// NewUnmarshaler creates an Unmarshaler with the given options. By default it
// uses a new Identifier with default settings.
func NewUnmarshaler(opts ...unmarshalerOption) *Unmarshaler {
	u := &Unmarshaler{identifier: NewIdentifier()}
	for _, opt := range opts {
		opt(u)
	}
	return u
}

// Unmarshal reads from r, identifies the SBOM format, and parses the document
// into a [Document]. It returns [ErrUnknownFormat] if the input is not a
// recognized SBOM, [ErrEmptyInput] if the reader is empty, and
// [ErrUnsupportedFormat] for recognized but unsupported formats.
func (u *Unmarshaler) Unmarshal(r io.Reader) (*Document, error) {
	ir, err := u.identifier.Identify(r)
	if err != nil {
		return nil, fmt.Errorf("identify: %w", err)
	}

	switch ir.Format.SBOMStandard {
	case SBOMStandardSPDX:
		doc, err := parseSPDX(ir.Format, ir.Reader)
		if err != nil {
			return nil, fmt.Errorf("parse spdx: %w", err)
		}
		return doc, nil
	case SBOMStandardCycloneDX:
		doc, err := parseCycloneDX(ir.Format, ir.Reader)
		if err != nil {
			return nil, fmt.Errorf("parse cyclonedx: %w", err)
		}
		return doc, nil
	default:
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedFormat, ir.Format.SBOMStandard)
	}
}
