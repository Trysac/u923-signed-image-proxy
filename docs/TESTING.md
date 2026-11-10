# Testing

## Running

- `go test -cover .`: Run unit and property tests with coverage requirements (must be > 80%).
- `go run ./scripts/check`: Run full gate suite including static checks.

## Layout and Policy

- Tests reside in `<file>_test.go` and use the `signedimageproxy_test` package to exercise the public API.
- Deterministic: Tests use injected `Clock` and `Resolver`/`Dial` mocks to simulate network conditions without actual I/O.
- Table-driven tests: Prefer `t.Run` for coverage of varied input scenarios.
- Conformance: CI-tagged tests (via `//go:build conformance`) verify behavior against live network fixtures where necessary, managed via environment tags.