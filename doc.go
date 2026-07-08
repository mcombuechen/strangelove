// Package strangelove provides streaming-first SBOM identification and parsing.
//
// It auto-detects and unmarshals SPDX and CycloneDX documents into a unified
// in-memory representation without buffering the entire input into memory.
//
// # Quick Start
//
// The primary entry point is [Unmarshaler]:
//
//	doc, err := strangelove.NewUnmarshaler().Unmarshal(reader)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println("Format:", doc.Format)
//
// # Identification Only
//
// Use [Identifier] directly when you only need format detection:
//
//	result, err := strangelove.NewIdentifier().Identify(reader)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(result.Format.SBOMStandard)
//
// # Errors
//
// The package returns sentinel errors that can be checked with errors.Is:
//
//   - [ErrUnknownFormat] — the input was not recognized as an SBOM
//   - [ErrEmptyInput] — no data was provided
//   - [ErrUnsupportedFormat] — the format was recognized but isn't supported
package strangelove
