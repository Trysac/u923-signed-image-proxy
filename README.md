# signed-image-proxy

[![Go Reference](https://pkg.go.dev/badge/github.com/Trysac/u923-signed-image-proxy.svg)](https://pkg.go.dev/github.com/Trysac/u923-signed-image-proxy)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/Trysac/u923-signed-image-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u923-signed-image-proxy/actions/workflows/ci.yml)

Image proxy that resizes and crops on demand from HMAC-signed URLs, with an ETag-aware bounded cache and SSRF protection on every fetch

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and what
they do today without it. Replace this paragraph when the first real feature lands.

## Install

```sh
go get github.com/Trysac/u923-signed-image-proxy
```

Requires Go 1.23 or newer. No dependencies outside the standard library.

## Usage

```go
package main

import (
	"errors"
	"fmt"

	"github.com/Trysac/u923-signed-image-proxy"
)

func main() {
	// Normalize trims surrounding whitespace and lower-cases the text.
	out, _ := signedimageproxy.Normalize("  Hello World ")
	fmt.Println(out) // -> "hello world"

	// Blank input is rejected explicitly instead of returning an empty string.
	if _, err := signedimageproxy.Normalize("   "); errors.Is(err, signedimageproxy.ErrBlank) {
		fmt.Println("rejected:", err)
	}
}
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
