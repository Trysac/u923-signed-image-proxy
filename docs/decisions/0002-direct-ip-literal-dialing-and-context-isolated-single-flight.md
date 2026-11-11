# Direct IP-Literal Dialing and Context-Isolated Single-Flight Image Processing

Status: accepted (generated, pending human review)

## Context

An on-demand image proxy faces two critical operational risks: DNS rebinding between SSRF validation and socket connection, and cache stampedes where one slow or cancelled client affects concurrent callers for the same image.

## Decision

Resolve hostnames once per hop via the injected Resolver, verify all returned netip.Addr values after Unmap(), and pass the verified IP literal directly into the transport's DialContext while preserving the HTTP Host header and TLS ServerName. Deduplicate concurrent misses per signed path using a single-flight coordinator running under context.WithoutCancel with FetchTimeout, and use golang.org/x/image/draw CatmullRom for high-quality resampling.

## Consequences

DNS rebinding between resolution and connection is eliminated, callers can cancel their own HTTP requests without aborting shared upstream fetches for remaining callers, and external dependencies are limited strictly to golang.org/x/image.
