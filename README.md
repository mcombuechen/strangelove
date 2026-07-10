<div align="center">
  <img src="mascot.png" alt="strangelove mascot" width="320">
</div>

# strangelove

### How I Learned to Stop Worrying and Love the SBOM.

`strangelove` is a simple, streaming-first SBOM parsing and identification library for Go. It auto-detects, identifies, and unmarshals both **SPDX** and **CycloneDX** documents into a single, predictable Go representation with zero boilerplate.

There is no need to buffer files into memory or deal with incompatible format schemas: just pass any `io.Reader` and `strangelove` will extract a unified component inventory for you.

## Supported Standards and Formats

| Standard | Serializations | Target Versions |
|---|---|---|
| **CycloneDX** | JSON, XML | v1.4, v1.5, v1.6 |
| **SPDX** | JSON, Tag-Value, RDF | v2.2, v2.3 |

## Usage

### Read any SBOM

Pass any SBOM stream (CycloneDX JSON/XML or SPDX JSON/Tag-Value) to `Unmarshal`. It will automatically detect the format, version, and serialization, then parse it into a unified representation:

```go
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/mcombuechen/strangelove"
)

func main() {
	file, err := os.Open("bom.json")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	doc, err := strangelove.Unmarshal(file)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Format: %s (v%s) [%s]\n",
		doc.Format.SBOMStandard,
		doc.Format.SpecVersion,
		doc.Format.Serialization)
	fmt.Printf("Created: %s\n\n", doc.Meta.CreatedAt)

	for _, c := range doc.Components {
		fmt.Printf(" - %s@%s (purl: %s)\n", c.Name, c.Version, c.PackageURL)
	}
}
```
