// Package signedimageproxy is a small, dependency-free Go library: Image proxy that resizes and crops on demand from HMAC-signed URLs, with an ETag-aware bounded cache and SSRF protection on every fetch
//
// The public API is every exported identifier of this root package. Functions are pure: they do
// no I/O, keep no global mutable state and report invalid input through returned errors.
package signedimageproxy
