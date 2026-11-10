# Architecture

## Purpose

`github.com/Trysac/u923-signed-image-proxy` is a small, dependency-free Go library: Image proxy that resizes and crops on demand from HMAC-signed URLs, with an ETag-aware bounded cache and SSRF protection on every fetch

## Shape

```text
caller code --> package signedimageproxy (repository root)
                    |
                    +-- pure functions, no I/O, no global mutable state
                    +-- internal/ (optional private helpers)
```

- **Public API**: every exported identifier of the root package. Unexported identifiers and
  `internal/` packages may change without a major version.
- **Errors**: invalid input returns an error; exported sentinel errors (such as `ErrBlank`) let
  callers branch with `errors.Is`. The library never panics on input, prints or exits.
- **Side effects**: none. If a feature needs I/O, accept an interface (`io.Reader` or a small
  custom one) instead of opening resources, and record the choice in an ADR.

## Quality contract

`scripts/check` is the single definition of the gates; `fabrica.json` tells the factory and CI
how to run it. See [TESTING.md](TESTING.md).

## Decisions

Architecture decisions are recorded in [decisions/](decisions/) as numbered ADRs.
