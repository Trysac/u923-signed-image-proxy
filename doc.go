// Package signedimageproxy provides an embeddable HTTP handler that resizes
// and crops images on demand from HMAC-SHA256 signed URLs, with ETag-aware
// byte-bounded LRU caching, single-flight request deduplication, and strict
// SSRF protection at resolution and dial time.
//
// # URL Format
//
// Requests use the path structure:
//
//	/<signature>/<options>/<source>
//
// where <source> is the raw base64url encoding (without padding) of the
// absolute source URL, <options> is a comma-separated list of key:value
// transformation parameters, and <signature> is the raw base64url encoding
// of HMAC-SHA256(key, "/" + options + "/" + source).
//
// # Threat Model
//
// Defended threats:
//   - Unsigned or tampered URLs: Every request is verified in constant time
//     against configured HMAC keys before parsing options or fetching.
//   - Expired URLs: The exp:<unix> option enforces a cryptographic expiration
//     timestamp checked against the configured clock.
//   - Server-Side Request Forgery (SSRF) including DNS rebinding and redirects:
//     Every hostname is resolved through the configured Resolver, every returned
//     address is unmapped and checked against private, loopback, link-local,
//     CGNAT, multicast, broadcast, documentation, benchmark, and unspecified
//     ranges, and the HTTP transport dials the verified IP literal directly
//     while preserving the Host header and TLS ServerName. Redirects (up to 3)
//     re-run full URL and IP validation.
//   - Decompression bombs: image.DecodeConfig reads headers first and rejects
//     images where width * height exceeds MaxPixels before allocating pixel
//     buffers in image.Decode.
//   - Oversized downloads: Upstream bodies are capped at MaxSourceBytes + 1
//     using io.LimitReader.
//   - Cache exhaustion: The in-memory LRU cache is strictly bounded by total
//     encoded byte size (MaxCacheBytes).
//
// Out of scope / Not defended:
//   - CPU exhaustion caused by a high rate of distinct validly signed URLs
//     (rate limiting or CDN shielding should be placed in front of the proxy).
//   - Signing key compromise (keys may be rotated using Config.Keys).
//   - Exploits in the underlying Go standard library image decoders beyond
//     header dimension checks.
package signedimageproxy
