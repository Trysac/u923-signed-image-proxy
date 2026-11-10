# signed-image-proxy

Web applications that resize user images on the fly risk open proxy vulnerabilities, including SSRF against cloud metadata or internal services and CPU exhaustion from endless resize variants. This package provides an embeddable Go `http.Handler` and CLI that safely resizes and crops images on demand, exclusively serving URLs signed with a server-side HMAC-SHA256 key, enforcing SSRF protections at the dial and resolution layer, and employing an ETag-aware, byte-bounded LRU cache.

## Installation

```bash
go get github.com/Trysac/u923-signed-image-proxy
```

## Usage

```go
import "github.com/Trysac/u923-signed-image-proxy"

func main() {
	key := []byte("0123456789abcdef")
	path := signedimageproxy.Sign(key, "w:200,h:200,fit:cover", "https://img.example.com/photo.png")
	proxy, _ := signedimageproxy.New(signedimageproxy.Config{Keys: [][]byte{key}})
	http.Handle("/", proxy)
}
```

## API Summary

- `Sign(key []byte, options, sourceURL string) string`: Generates a URL path signature.
- `New(cfg Config) (*Proxy, error)`: Creates the handler.
- **Limits**: Configurable `MaxPixels` (default 50M), `MaxSourceBytes` (default 20MiB), `MaxOutputSide` (default 4096), `MaxCacheBytes` (default 256MiB), and `FetchTimeout` (default 10s).
- **Options**: `w`, `h` (pixels, at least one required); `fit` (fill, contain, cover); `fmt` (png, jpeg); `q` (quality 1-100); `exp` (unix timestamp).
- **Errors**: `403` (invalid signature/expired/forbidden address), `400` (invalid options/source), `415` (unsupported content type), `422` (too many pixels), `502` (source too large).

## Why not imgproxy?

Unlike imgproxy, which is a standalone full-service application, this package is an embeddable Go library designed for internal services needing strict control over SSRF defense, signing logic, and resource usage within a single binary.

See [docs/SECURITY.md](docs/SECURITY.md).