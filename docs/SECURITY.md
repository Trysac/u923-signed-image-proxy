# Security Policy and Threat Model

## Threat Model

`signedimageproxy` defends against:

1. **Unsigned/Tampered URLs**: Enforces HMAC-SHA256 verification using constant-time `hmac.Equal`.
2. **SSRF**: Refuses private/loopback/reserved IP addresses (RFC 1918, link-local, etc.) by validating resolved addresses at dial time; uses direct IP dialing to mitigate DNS rebinding; caps redirects at 3.
3. **Decompression Bombs**: Uses `image.DecodeConfig` to cap total pixels (`MaxPixels`) before allocating memory for full decode.
4. **Oversized Downloads**: Limits source body streams to `MaxSourceBytes`.
5. **Cache Exhaustion**: Tracks total byte usage in the LRU cache against `MaxCacheBytes`.
6. **Content-Sniffing**: Sets `X-Content-Type-Options: nosniff` and a restrictive `Content-Security-Policy`.

### Not Defended

- **CPU Exhaustion**: Does not implement rate limiting; deploy behind a CDN or WAF.
- **Key Compromise**: Requires secure management of `Config.Keys`.
- **Zero-Day Decoders**: Relies on Go's standard library `image/*` packages.