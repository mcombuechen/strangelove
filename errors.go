package strangelove

import "errors"

var (
	// ErrUnknownFormat is returned when the input cannot be identified as
	// a supported SBOM format.
	ErrUnknownFormat = errors.New("unknown SBOM format")

	// ErrEmptyInput is returned when the reader contains no data.
	ErrEmptyInput = errors.New("empty input")

	// ErrUnsupportedFormat is returned when the format is recognized but
	// parsing is not yet implemented for that format or serialization.
	ErrUnsupportedFormat = errors.New("unsupported SBOM format")
)
