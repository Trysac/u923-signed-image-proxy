# Architecture

## Overview

`signedimageproxy` is structured as a single, self-contained library package with a thin CLI entrypoint in `cmd/signed-image-proxy`.

## Request Pipeline

Every incoming HTTP request executes checks in a strict deterministic order:

1. **Path Shape & Signature Verification (`403`)**: Splits `/<signature>/<options>/<source>` and verifies the 43-character raw base64url HMAC-SHA256 signature against `Config.Keys` using `hmac.Equal`.
2. **Expiration (`403`)**: Parses the `exp` option if present and compares it against `Config.Clock()`.
3. **Options Validation (`400`)**: Validates `w`, `h`, `fit`, `fmt`, `q`, and `exp`, rejecting unknown or duplicate option keys.
4. **Cache Lookup (`200` / `304`)**: Checks the byte-bounded LRU cache keyed by the full signed request path and handles `If-None-Match` ETag revalidation.
5. **Source URL Validation (`400`)**: Base64url-decodes the source URL and enforces `http`/`https`, no userinfo, and `AllowedHosts`.
6. **Single-Flight Fetch, Decode, Transform, Encode, and Store**:
   - Concurrent cache misses for the same path share one upstream fetch and image resize run under `context.WithoutCancel` bounded by `FetchTimeout`.
   - Each hop (up to 3 redirects) resolves hostnames via `Resolver`, checks that every IP is public, and dials the verified IP literal directly.
   - `image.DecodeConfig` enforces `MaxPixels` before `image.Decode` allocates pixel memory.
   - `golang.org/x/image/draw.CatmullRom` performs `fill`, `contain`, or `cover` resampling.
