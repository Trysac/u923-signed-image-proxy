# Project record

## Objective

Provide an embeddable, secure-by-default image proxy that resizes and crops on demand from HMAC-signed URLs, featuring an ETag-aware bounded cache and SSRF protection on every fetch.

## Scope

- HMAC-SHA256 signature verification for all incoming requests.
- Strict SSRF defense using direct IP dialing with hostname header spoofing.
- Resizing and cropping (fill, contain, cover) via `golang.org/x/image/draw`.
- ETag-aware LRU cache for responses.
- CLI for serving and signing URLs.

## Out of Scope

- WebP and AVIF support.
- Animated image processing.
- Smart cropping (e.g., face detection).
- Watermarking.
- Persistent (disk-based) caching.

## Factory run u923 (measured from API usage)

| Date (UTC) | Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|---|
| 2026-11-10 | generation | google/gemini-4-argon | yes | 0 | 0 | 0 | 0 | 0.0000 |
| 2026-11-10 | generation | google/gemini-4-argon | yes | 5980 | 27117 | 0 | 0 | 0.5663 |
| 2026-11-10 | fix-1 | google/gemini-3.8-flash | no | 314127 | 1882 | 0 | 170366 | 0.2554 |
| 2026-11-10 | audit | google/gemini-3.8-flash | no | 278027 | 893 | 0 | 318023 | 0.2357 |
| 2026-11-10 | docs | google/gemini-3.1-flash-lite | no | 6178 | 1323 | 0 | 0 | 0.0035 |

Total: $1.0609. Prices: vertex line, as measured by its adapter. Providers serve the current version of each model id, so the date tells which version answered; versions, launch stages and price sources per line are in the factory's model register (docs/MODELS.md).
