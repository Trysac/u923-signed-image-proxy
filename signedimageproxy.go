package signedimageproxy

import (
	"bytes"
	"container/list"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/image/draw"
)

// Default limits and configuration values.
const (
	DefaultMaxSourceBytes int64         = 20 * 1024 * 1024  // 20 MiB
	DefaultMaxPixels      int64         = 50_000_000        // 50 megapixels
	DefaultMaxOutputSide  int           = 4096              // 4096 px
	DefaultMaxCacheBytes  int64         = 256 * 1024 * 1024 // 256 MiB
	DefaultCacheMaxAge    time.Duration = 24 * time.Hour
	DefaultFetchTimeout   time.Duration = 10 * time.Second
	DefaultJPEGQuality    int           = 85
	MaxPathLength         int           = 8192
	MaxRedirects          int           = 3
	MinKeyLength          int           = 16
)

// Error represents a typed error from the image proxy with a stable machine-readable
// Code and corresponding HTTP Status code.
type Error struct {
	Code    string
	Status  int
	Message string
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return e.Code
}

// Is reports whether target matches this Error by Code and Status.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return e.Code == t.Code && (t.Status == 0 || e.Status == t.Status)
}

// Sentinel errors exported by the package.
var (
	ErrInvalidConfig    = &Error{Code: "invalid_config", Status: http.StatusInternalServerError, Message: "invalid configuration"}
	ErrInvalidSignature = &Error{Code: "invalid_signature", Status: http.StatusForbidden, Message: "invalid signature"}
	ErrExpired          = &Error{Code: "expired", Status: http.StatusForbidden, Message: "expired"}
	ErrInvalidOptions   = &Error{Code: "invalid_options", Status: http.StatusBadRequest, Message: "invalid options"}
	ErrInvalidSource    = &Error{Code: "invalid_source", Status: http.StatusBadRequest, Message: "invalid source"}
	ErrForbiddenAddress = &Error{Code: "forbidden_address", Status: http.StatusForbidden, Message: "forbidden address"}
	ErrSourceTooLarge   = &Error{Code: "source_too_large", Status: http.StatusBadGateway, Message: "source too large"}
	ErrUnsupportedMedia = &Error{Code: "unsupported_media_type", Status: http.StatusUnsupportedMediaType, Message: "unsupported media type"}
	ErrImageTooLarge    = &Error{Code: "image_too_large", Status: http.StatusUnprocessableEntity, Message: "image too large"}
	ErrDecodeFailed     = &Error{Code: "decode_failed", Status: http.StatusUnprocessableEntity, Message: "invalid image"}
	ErrUpstreamFailed   = &Error{Code: "upstream_failed", Status: http.StatusBadGateway, Message: "upstream fetch failed"}
)

// Event carries sanitized telemetry about a processed request.
// It intentionally excludes source URLs, query parameters, and key material.
type Event struct {
	Kind     string
	Status   int
	CacheHit bool
}

// Config configures a Proxy instance.
type Config struct {
	// Keys holds the HMAC-SHA256 secret keys. At least one key is required,
	// and every key must be at least 16 bytes. The first key is used by Sign
	// conventions, while all keys are accepted during verification.
	Keys [][]byte

	// Resolver looks up IP addresses for a hostname. Defaults to net.DefaultResolver.
	Resolver func(ctx context.Context, host string) ([]netip.Addr, error)

	// Dial establishes a network connection to an address. Defaults to net.Dialer.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)

	// AllowPrivate permits connecting to loopback, private, link-local, and
	// other reserved IP ranges when true.
	AllowPrivate bool

	// AllowedHosts restricts source URLs to the listed hostnames (case-insensitive).
	// When empty, any public host is permitted.
	AllowedHosts []string

	// MaxSourceBytes caps the upstream response body size. Defaults to 20 MiB.
	MaxSourceBytes int64

	// MaxPixels caps width * height of the decoded source image. Defaults to 50,000,000.
	MaxPixels int64

	// MaxOutputSide caps requested w and h values. Defaults to 4096.
	MaxOutputSide int

	// MaxCacheBytes caps the total byte size of cached images. Defaults to 256 MiB.
	// If negative, caching is disabled.
	MaxCacheBytes int64

	// CacheMaxAge sets the max-age directive in Cache-Control headers. Defaults to 24h.
	CacheMaxAge time.Duration

	// FetchTimeout sets the timeout for upstream image fetches. Defaults to 10s.
	FetchTimeout time.Duration

	// Clock returns the current time for expiry checks. Defaults to time.Now.
	Clock func() time.Time

	// OnEvent is an optional hook called once per completed HTTP request.
	OnEvent func(Event)
}

// Proxy is an HTTP handler that verifies, fetches, transforms, and caches images.
type Proxy struct {
	keys           [][]byte
	resolver       func(ctx context.Context, host string) ([]netip.Addr, error)
	dial           func(ctx context.Context, network, addr string) (net.Conn, error)
	allowPrivate   bool
	allowedHosts   map[string]struct{}
	maxSourceBytes int64
	maxPixels      int64
	maxOutputSide  int
	maxCacheBytes  int64
	cacheMaxAge    time.Duration
	fetchTimeout   time.Duration
	clock          func() time.Time
	onEvent        func(Event)

	cache *lruCache

	sfMu    sync.Mutex
	sfCalls map[string]*sfCall
}

type sfCall struct {
	done chan struct{}
	res  *cacheEntry
	err  *Error
}

// Sign returns a signed request path of the form "/<signature>/<options>/<source>"
// where <source> is raw base64url(sourceURL) and <signature> is raw base64url of
// HMAC-SHA256(key, "/" + options + "/" + source).
func Sign(key []byte, options, sourceURL string) string {
	encodedSource := base64.RawURLEncoding.EncodeToString([]byte(sourceURL))
	payload := "/" + options + "/" + encodedSource
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return "/" + sig + payload
}

// New validates cfg and constructs a new Proxy.
func New(cfg Config) (*Proxy, error) {
	if len(cfg.Keys) == 0 {
		return nil, fmt.Errorf("%w: at least one key is required", ErrInvalidConfig)
	}
	keysCopy := make([][]byte, len(cfg.Keys))
	for i, k := range cfg.Keys {
		if len(k) < MinKeyLength {
			return nil, fmt.Errorf("%w: key %d is shorter than %d bytes", ErrInvalidConfig, i, MinKeyLength)
		}
		kc := make([]byte, len(k))
		copy(kc, k)
		keysCopy[i] = kc
	}

	resolver := cfg.Resolver
	if resolver == nil {
		resolver = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}

	dial := cfg.Dial
	if dial == nil {
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		dial = dialer.DialContext
	}

	maxSourceBytes := cfg.MaxSourceBytes
	if maxSourceBytes <= 0 {
		maxSourceBytes = DefaultMaxSourceBytes
	}

	maxPixels := cfg.MaxPixels
	if maxPixels <= 0 {
		maxPixels = DefaultMaxPixels
	}

	maxOutputSide := cfg.MaxOutputSide
	if maxOutputSide <= 0 {
		maxOutputSide = DefaultMaxOutputSide
	}

	maxCacheBytes := cfg.MaxCacheBytes
	if maxCacheBytes == 0 {
		maxCacheBytes = DefaultMaxCacheBytes
	} else if maxCacheBytes < 0 {
		maxCacheBytes = 0
	}

	cacheMaxAge := cfg.CacheMaxAge
	if cacheMaxAge <= 0 {
		cacheMaxAge = DefaultCacheMaxAge
	}

	fetchTimeout := cfg.FetchTimeout
	if fetchTimeout <= 0 {
		fetchTimeout = DefaultFetchTimeout
	}

	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}

	allowedHosts := make(map[string]struct{}, len(cfg.AllowedHosts))
	for _, h := range cfg.AllowedHosts {
		trimmed := strings.ToLower(strings.TrimSpace(h))
		if trimmed != "" {
			allowedHosts[trimmed] = struct{}{}
		}
	}

	return &Proxy{
		keys:           keysCopy,
		resolver:       resolver,
		dial:           dial,
		allowPrivate:   cfg.AllowPrivate,
		allowedHosts:   allowedHosts,
		maxSourceBytes: maxSourceBytes,
		maxPixels:      maxPixels,
		maxOutputSide:  maxOutputSide,
		maxCacheBytes:  maxCacheBytes,
		cacheMaxAge:    cacheMaxAge,
		fetchTimeout:   fetchTimeout,
		clock:          clock,
		onEvent:        cfg.OnEvent,
		cache:          newLRUCache(maxCacheBytes),
		sfCalls:        make(map[string]*sfCall),
	}, nil
}

// ServeHTTP implements http.Handler.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		p.writeError(w, &Error{Code: "method_not_allowed", Status: http.StatusMethodNotAllowed, Message: "method not allowed"})
		return
	}

	reqPath := r.URL.EscapedPath()
	if reqPath == "" {
		reqPath = r.URL.Path
	}
	if len(reqPath) > MaxPathLength {
		p.writeError(w, ErrInvalidSignature)
		return
	}

	// 1. Path shape and signature check (403).
	sigPart, optsPart, srcPart, ok := splitSignedPath(reqPath)
	if !ok || !p.verifySignature(sigPart, optsPart, srcPart) {
		p.writeError(w, ErrInvalidSignature)
		return
	}

	// 2. Expiry check (403) and 3. Options validation (400).
	// We inspect options; if exp is present and valid, check expiry first.
	opts, expErr := parseOptions(optsPart, p.maxOutputSide, p.clock())
	if expErr != nil {
		p.writeError(w, expErr)
		return
	}

	// 4. Cache lookup.
	if entry, hit := p.cache.get(reqPath); hit {
		p.serveEntry(w, r, entry, true)
		return
	}

	// 5. Source URL validation (400 "invalid source").
	srcURL, srcErr := p.parseAndValidateSourceURL(srcPart)
	if srcErr != nil {
		p.writeError(w, srcErr)
		return
	}

	// 6. Single-flight fetch, decode, transform, encode, cache store.
	entry, err := p.doSingleFlight(r.Context(), reqPath, srcURL, opts)
	if err != nil {
		p.writeError(w, err)
		return
	}

	p.serveEntry(w, r, entry, false)
}

func (p *Proxy) serveEntry(w http.ResponseWriter, r *http.Request, entry *cacheEntry, cacheHit bool) {
	w.Header().Set("ETag", entry.etag)
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(p.cacheMaxAge.Seconds())))

	if matchETag(r.Header.Get("If-None-Match"), entry.etag) {
		w.WriteHeader(http.StatusNotModified)
		p.emitEvent("not_modified", http.StatusNotModified, cacheHit)
		return
	}

	w.Header().Set("Content-Type", entry.contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(entry.body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(entry.body)
	}
	kind := "fetched"
	if cacheHit {
		kind = "cache_hit"
	}
	p.emitEvent(kind, http.StatusOK, cacheHit)
}

func (p *Proxy) writeError(w http.ResponseWriter, err *Error) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(err.Status)
	_, _ = io.WriteString(w, err.Error())
	p.emitEvent(err.Code, err.Status, false)
}

func (p *Proxy) emitEvent(kind string, status int, cacheHit bool) {
	if p.onEvent != nil {
		p.onEvent(Event{
			Kind:     kind,
			Status:   status,
			CacheHit: cacheHit,
		})
	}
}

func splitSignedPath(path string) (sig, opts, src string, ok bool) {
	if !strings.HasPrefix(path, "/") {
		return "", "", "", false
	}
	rest := path[1:]
	slash1 := strings.IndexByte(rest, '/')
	if slash1 <= 0 {
		return "", "", "", false
	}
	sig = rest[:slash1]
	rest2 := rest[slash1+1:]
	slash2 := strings.IndexByte(rest2, '/')
	if slash2 <= 0 {
		return "", "", "", false
	}
	opts = rest2[:slash2]
	src = rest2[slash2+1:]
	if src == "" || strings.ContainsRune(src, '/') {
		return "", "", "", false
	}
	return sig, opts, src, true
}

func (p *Proxy) verifySignature(sigB64, opts, src string) bool {
	if len(sigB64) != 43 {
		return false
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil || len(sigBytes) != sha256.Size {
		return false
	}
	payload := []byte("/" + opts + "/" + src)
	matched := false
	for _, key := range p.keys {
		mac := hmac.New(sha256.New, key)
		mac.Write(payload)
		expected := mac.Sum(nil)
		if hmac.Equal(sigBytes, expected) {
			matched = true
		}
	}
	return matched
}

type transformOptions struct {
	w       int
	h       int
	fit     string
	format  string
	quality int
	exp     int64
	hasExp  bool
}

func parseOptions(raw string, maxSide int, now time.Time) (transformOptions, *Error) {
	opts := transformOptions{
		fit:     "contain",
		quality: DefaultJPEGQuality,
	}
	if raw == "" {
		return opts, ErrInvalidOptions
	}
	parts := strings.Split(raw, ",")
	seen := make(map[string]bool, len(parts))
	invalidOpt := false

	for _, part := range parts {
		colon := strings.IndexByte(part, ':')
		if colon <= 0 || colon == len(part)-1 {
			invalidOpt = true
			continue
		}
		name := part[:colon]
		val := part[colon+1:]
		if seen[name] {
			invalidOpt = true
			continue
		}
		seen[name] = true

		switch name {
		case "w":
			n, err := strconv.Atoi(val)
			if err != nil || n < 1 || n > maxSide {
				invalidOpt = true
				continue
			}
			opts.w = n
		case "h":
			n, err := strconv.Atoi(val)
			if err != nil || n < 1 || n > maxSide {
				invalidOpt = true
				continue
			}
			opts.h = n
		case "fit":
			if val != "fill" && val != "contain" && val != "cover" {
				invalidOpt = true
				continue
			}
			opts.fit = val
		case "fmt":
			if val != "png" && val != "jpeg" {
				invalidOpt = true
				continue
			}
			opts.format = val
		case "q":
			n, err := strconv.Atoi(val)
			if err != nil || n < 1 || n > 100 {
				invalidOpt = true
				continue
			}
			opts.quality = n
		case "exp":
			exp, err := strconv.ParseInt(val, 10, 64)
			if err != nil || exp < 0 {
				invalidOpt = true
				continue
			}
			opts.exp = exp
			opts.hasExp = true
		default:
			invalidOpt = true
		}
	}

	// Order of checks: expiry (403) comes before options validation (400).
	if opts.hasExp && now.Unix() > opts.exp {
		return opts, ErrExpired
	}

	if invalidOpt || (opts.w == 0 && opts.h == 0) {
		return opts, ErrInvalidOptions
	}

	return opts, nil
}

func (p *Proxy) parseAndValidateSourceURL(srcB64 string) (*url.URL, *Error) {
	rawBytes, err := base64.RawURLEncoding.DecodeString(srcB64)
	if err != nil || len(rawBytes) == 0 || len(rawBytes) > 4096 {
		return nil, ErrInvalidSource
	}
	u, err := url.Parse(string(rawBytes))
	if err != nil {
		return nil, ErrInvalidSource
	}
	if err := p.validateParsedURL(u); err != nil {
		return nil, err
	}
	return u, nil
}

func (p *Proxy) validateParsedURL(u *url.URL) *Error {
	if u.Scheme != "http" && u.Scheme != "https" {
		return ErrInvalidSource
	}
	if u.User != nil {
		return ErrInvalidSource
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return ErrInvalidSource
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return ErrInvalidSource
		}
	}
	if len(p.allowedHosts) > 0 {
		if _, ok := p.allowedHosts[host]; !ok {
			return ErrInvalidSource
		}
	}
	return nil
}

var (
	cgnatPrefix      = netip.MustParsePrefix("100.64.0.0/10")
	docV4Prefix1     = netip.MustParsePrefix("192.0.2.0/24")
	docV4Prefix2     = netip.MustParsePrefix("198.51.100.0/24")
	docV4Prefix3     = netip.MustParsePrefix("203.0.113.0/24")
	ietfProtocolV4   = netip.MustParsePrefix("192.0.0.0/24")
	benchmarkV4      = netip.MustParsePrefix("198.18.0.0/15")
	reservedClassEV4 = netip.MustParsePrefix("240.0.0.0/4")
	thisNetV4        = netip.MustParsePrefix("0.0.0.0/8")
	docV6Prefix      = netip.MustParsePrefix("2001:db8::/32")
	benchmarkV6      = netip.MustParsePrefix("2001:2::/48")
	discardV6        = netip.MustParsePrefix("100::/64")
	ipv4MappedV6     = netip.MustParsePrefix("::ffff:0:0/96")
	nat64WellKnown   = netip.MustParsePrefix("64:ff9b::/96")
	nat64Local       = netip.MustParsePrefix("64:ff9b:1::/48")
	to6v6Prefix      = netip.MustParsePrefix("2002::/16")
	teredoPrefix     = netip.MustParsePrefix("2001::/32")
)

// isPublicAddr returns true only if addr (after unmapping IPv4-mapped IPv6 addresses)
// is a globally routable unicast public IP address.
func isPublicAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	if addr.IsLoopback() ||
		addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() ||
		addr.IsUnspecified() {
		return false
	}
	if addr.Is4() {
		ov := addr.As4()
		if ov == [4]byte{255, 255, 255, 255} {
			return false
		}
		if thisNetV4.Contains(addr) ||
			cgnatPrefix.Contains(addr) ||
			docV4Prefix1.Contains(addr) ||
			docV4Prefix2.Contains(addr) ||
			docV4Prefix3.Contains(addr) ||
			ietfProtocolV4.Contains(addr) ||
			benchmarkV4.Contains(addr) ||
			reservedClassEV4.Contains(addr) {
			return false
		}
		return true
	}
	if docV6Prefix.Contains(addr) ||
		benchmarkV6.Contains(addr) ||
		discardV6.Contains(addr) ||
		ipv4MappedV6.Contains(addr) ||
		nat64WellKnown.Contains(addr) ||
		nat64Local.Contains(addr) ||
		to6v6Prefix.Contains(addr) ||
		teredoPrefix.Contains(addr) {
		return false
	}
	return true
}

func (p *Proxy) resolveAndCheck(ctx context.Context, host string) (netip.Addr, *Error) {
	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{ip}
	} else {
		resolved, err := p.resolver(ctx, host)
		if err != nil || len(resolved) == 0 {
			return netip.Addr{}, ErrUpstreamFailed
		}
		addrs = resolved
	}

	for _, a := range addrs {
		unmapped := a.Unmap()
		if !p.allowPrivate && !isPublicAddr(unmapped) {
			return netip.Addr{}, ErrForbiddenAddress
		}
	}
	return addrs[0].Unmap(), nil
}

func (p *Proxy) doSingleFlight(callerCtx context.Context, key string, srcURL *url.URL, opts transformOptions) (*cacheEntry, *Error) {
	p.sfMu.Lock()
	if entry, hit := p.cache.get(key); hit {
		p.sfMu.Unlock()
		return entry, nil
	}
	if call, inflight := p.sfCalls[key]; inflight {
		p.sfMu.Unlock()
		select {
		case <-call.done:
			return call.res, call.err
		case <-callerCtx.Done():
			return nil, &Error{Code: "request_cancelled", Status: 499, Message: "request cancelled"}
		}
	}

	call := &sfCall{done: make(chan struct{})}
	p.sfCalls[key] = call
	p.sfMu.Unlock()

	go func() {
		workCtx, cancel := context.WithTimeout(context.WithoutCancel(callerCtx), p.fetchTimeout)
		defer cancel()

		res, err := p.fetchAndTransform(workCtx, srcURL, opts)
		if err == nil {
			p.cache.put(key, res)
		}

		p.sfMu.Lock()
		call.res = res
		call.err = err
		delete(p.sfCalls, key)
		close(call.done)
		p.sfMu.Unlock()
	}()

	select {
	case <-call.done:
		return call.res, call.err
	case <-callerCtx.Done():
		return nil, &Error{Code: "request_cancelled", Status: 499, Message: "request cancelled"}
	}
}

func (p *Proxy) fetchAndTransform(ctx context.Context, initialURL *url.URL, opts transformOptions) (*cacheEntry, *Error) {
	bodyBytes, err := p.fetchSource(ctx, initialURL)
	if err != nil {
		return nil, err
	}

	// Check dimensions via DecodeConfig before decoding pixels.
	cfg, srcFormat, decErr := image.DecodeConfig(bytes.NewReader(bodyBytes))
	if decErr != nil {
		return nil, ErrDecodeFailed
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || int64(cfg.Width)*int64(cfg.Height) > p.maxPixels {
		return nil, ErrImageTooLarge
	}
	if srcFormat != "png" && srcFormat != "jpeg" && srcFormat != "gif" {
		return nil, ErrUnsupportedMedia
	}

	var srcImg image.Image
	if srcFormat == "gif" {
		// Decode first frame.
		srcImg, decErr = gif.Decode(bytes.NewReader(bodyBytes))
	} else {
		srcImg, _, decErr = image.Decode(bytes.NewReader(bodyBytes))
	}
	if decErr != nil {
		return nil, ErrDecodeFailed
	}

	dstImg := transformImage(srcImg, opts)

	outFmt := opts.format
	if outFmt == "" {
		if srcFormat == "gif" {
			outFmt = "png"
		} else {
			outFmt = srcFormat
		}
	}

	var outBuf bytes.Buffer
	var contentType string
	switch outFmt {
	case "jpeg":
		contentType = "image/jpeg"
		if encErr := jpeg.Encode(&outBuf, dstImg, &jpeg.Options{Quality: opts.quality}); encErr != nil {
			return nil, ErrDecodeFailed
		}
	default:
		contentType = "image/png"
		if encErr := png.Encode(&outBuf, dstImg); encErr != nil {
			return nil, ErrDecodeFailed
		}
	}

	encoded := outBuf.Bytes()
	sum := sha256.Sum256(encoded)
	etag := `"` + hex.EncodeToString(sum[:16]) + `"`

	return &cacheEntry{
		body:        encoded,
		contentType: contentType,
		etag:        etag,
	}, nil
}

func (p *Proxy) fetchSource(ctx context.Context, initialURL *url.URL) ([]byte, *Error) {
	currentURL := initialURL
	for redirectCount := 0; redirectCount <= MaxRedirects; redirectCount++ {
		if err := p.validateParsedURL(currentURL); err != nil {
			if redirectCount > 0 {
				return nil, ErrForbiddenAddress
			}
			return nil, err
		}

		host := currentURL.Hostname()
		port := currentURL.Port()
		if port == "" {
			if currentURL.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}

		checkedIP, ipErr := p.resolveAndCheck(ctx, host)
		if ipErr != nil {
			return nil, ipErr
		}

		dialTarget := net.JoinHostPort(checkedIP.String(), port)
		transport := &http.Transport{
			DialContext: func(dCtx context.Context, network, _ string) (net.Conn, error) {
				return p.dial(dCtx, network, dialTarget)
			},
			TLSClientConfig: &tls.Config{
				ServerName: host,
				MinVersion: tls.VersionTLS12,
			},
			DisableKeepAlives: true,
		}

		targetURL := &url.URL{
			Scheme:   currentURL.Scheme,
			Host:     currentURL.Host,
			Path:     currentURL.Path,
			RawQuery: currentURL.RawQuery,
		}

		req := (&http.Request{
			Method:     http.MethodGet,
			URL:        targetURL,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Host:       currentURL.Host,
		}).WithContext(ctx)

		resp, doErr := transport.RoundTrip(req)
		if doErr != nil {
			return nil, ErrUpstreamFailed
		}

		// Handle redirects manually so every hop is re-validated.
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc := resp.Header.Get("Location")
			_ = resp.Body.Close()
			if loc == "" || redirectCount == MaxRedirects {
				return nil, ErrUpstreamFailed
			}
			nextURL, parseErr := currentURL.Parse(loc)
			if parseErr != nil {
				return nil, ErrUpstreamFailed
			}
			currentURL = nextURL
			continue
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, ErrUpstreamFailed
		}

		ct := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type")))
		if !strings.HasPrefix(ct, "image/") {
			_ = resp.Body.Close()
			return nil, ErrUnsupportedMedia
		}

		limited := io.LimitReader(resp.Body, p.maxSourceBytes+1)
		data, readErr := io.ReadAll(limited)
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, ErrUpstreamFailed
		}
		if int64(len(data)) > p.maxSourceBytes {
			return nil, ErrSourceTooLarge
		}
		return data, nil
	}
	return nil, ErrUpstreamFailed
}

func transformImage(src image.Image, opts transformOptions) image.Image {
	b := src.Bounds()
	srcW := b.Dx()
	srcH := b.Dy()

	targetW := opts.w
	targetH := opts.h
	if targetW == 0 {
		targetW = maxInt(1, int(math.Round(float64(srcW)*float64(targetH)/float64(srcH))))
	} else if targetH == 0 {
		targetH = maxInt(1, int(math.Round(float64(srcH)*float64(targetW)/float64(srcW))))
	}

	switch opts.fit {
	case "fill":
		dst := image.NewRGBA(image.Rect(0, 0, targetW, targetH))
		draw.CatmullRom.Scale(dst, dst.Bounds(), src, b, draw.Over, nil)
		return dst

	case "cover":
		scaleX := float64(targetW) / float64(srcW)
		scaleY := float64(targetH) / float64(srcH)
		scale := math.Max(scaleX, scaleY)
		scaledW := maxInt(targetW, int(math.Round(float64(srcW)*scale)))
		scaledH := maxInt(targetH, int(math.Round(float64(srcH)*scale)))

		scaled := image.NewRGBA(image.Rect(0, 0, scaledW, scaledH))
		draw.CatmullRom.Scale(scaled, scaled.Bounds(), src, b, draw.Over, nil)

		offsetX := (scaledW - targetW) / 2
		offsetY := (scaledH - targetH) / 2
		cropRect := image.Rect(offsetX, offsetY, offsetX+targetW, offsetY+targetH)
		dst := image.NewRGBA(image.Rect(0, 0, targetW, targetH))
		draw.Draw(dst, dst.Bounds(), scaled, cropRect.Min, draw.Src)
		return dst

	default: // "contain"
		scaleX := float64(targetW) / float64(srcW)
		scaleY := float64(targetH) / float64(srcH)
		scale := math.Min(scaleX, scaleY)
		newW := maxInt(1, int(math.Round(float64(srcW)*scale)))
		newH := maxInt(1, int(math.Round(float64(srcH)*scale)))

		dst := image.NewRGBA(image.Rect(0, 0, newW, newH))
		draw.CatmullRom.Scale(dst, dst.Bounds(), src, b, draw.Over, nil)
		return dst
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func matchETag(ifNoneMatch, etag string) bool {
	inm := strings.TrimSpace(ifNoneMatch)
	if inm == "" {
		return false
	}
	if inm == "*" {
		return true
	}
	for _, part := range strings.Split(inm, ",") {
		candidate := strings.TrimSpace(part)
		candidate = strings.TrimPrefix(candidate, "W/")
		if candidate == etag {
			return true
		}
	}
	return false
}

type cacheEntry struct {
	key         string
	body        []byte
	contentType string
	etag        string
}

func (e *cacheEntry) size() int64 {
	return int64(len(e.body))
}

type lruCache struct {
	mu       sync.Mutex
	maxBytes int64
	curBytes int64
	ll       *list.List
	items    map[string]*list.Element
}

func newLRUCache(maxBytes int64) *lruCache {
	return &lruCache{
		maxBytes: maxBytes,
		ll:       list.New(),
		items:    make(map[string]*list.Element),
	}
}

func (c *lruCache) get(key string) (*cacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.maxBytes <= 0 {
		return nil, false
	}
	ele, ok := c.items[key]
	if !ok {
		return nil, false
	}
	c.ll.MoveToFront(ele)
	return ele.Value.(*cacheEntry), true
}

func (c *lruCache) put(key string, entry *cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	size := entry.size()
	if c.maxBytes <= 0 || size > c.maxBytes {
		return
	}
	entryCopy := &cacheEntry{
		key:         key,
		body:        entry.body,
		contentType: entry.contentType,
		etag:        entry.etag,
	}
	if ele, exists := c.items[key]; exists {
		old := ele.Value.(*cacheEntry)
		c.curBytes -= old.size()
		ele.Value = entryCopy
		c.curBytes += size
		c.ll.MoveToFront(ele)
	} else {
		ele := c.ll.PushFront(entryCopy)
		c.items[key] = ele
		c.curBytes += size
	}
	for c.curBytes > c.maxBytes && c.ll.Len() > 0 {
		back := c.ll.Back()
		if back == nil {
			break
		}
		evicted := back.Value.(*cacheEntry)
		c.ll.Remove(back)
		delete(c.items, evicted.key)
		c.curBytes -= evicted.size()
	}
}

// Run executes the signed-image-proxy CLI and returns an exit code (0 on success,
// 1 on runtime error, 2 on usage error).
//
// Supported subcommands:
//   - serve [-addr 127.0.0.1:8080]
//   - sign -options <options> <url>
//
// Both subcommands read comma-separated hex-encoded keys from IMGPROXY_KEYS.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: signed-image-proxy <serve|sign> [flags]")
		return 2
	}

	subcmd := args[0]
	switch subcmd {
	case "sign":
		fs := flag.NewFlagSet("sign", flag.ContinueOnError)
		fs.SetOutput(stderr)
		optsFlag := fs.String("options", "", "comma-separated image transform options")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if *optsFlag == "" || fs.NArg() != 1 {
			fmt.Fprintln(stderr, "usage: signed-image-proxy sign -options <options> <url>")
			return 2
		}
		keys, err := parseEnvKeys(os.Getenv("IMGPROXY_KEYS"))
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		path := Sign(keys[0], *optsFlag, fs.Arg(0))
		fmt.Fprintln(stdout, path)
		return 0

	case "serve":
		fs := flag.NewFlagSet("serve", flag.ContinueOnError)
		fs.SetOutput(stderr)
		addrFlag := fs.String("addr", "127.0.0.1:8080", "listen address")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if fs.NArg() != 0 {
			fmt.Fprintln(stderr, "usage: signed-image-proxy serve [-addr 127.0.0.1:8080]")
			return 2
		}
		keys, err := parseEnvKeys(os.Getenv("IMGPROXY_KEYS"))
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		proxy, err := New(Config{Keys: keys})
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		srv := &http.Server{
			Addr:              *addrFlag,
			Handler:           proxy,
			ReadHeaderTimeout: 5 * time.Second,
		}
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		return 0

	default:
		fmt.Fprintf(stderr, "unknown subcommand %q\n", subcmd)
		return 2
	}
}

func parseEnvKeys(raw string) ([][]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("IMGPROXY_KEYS environment variable is not set")
	}
	parts := strings.Split(raw, ",")
	keys := make([][]byte, 0, len(parts))
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		b, err := hex.DecodeString(p)
		if err != nil {
			return nil, fmt.Errorf("invalid hex in IMGPROXY_KEYS[%d]", i)
		}
		if len(b) < MinKeyLength {
			return nil, fmt.Errorf("key %d must be at least %d bytes", i, MinKeyLength)
		}
		keys = append(keys, b)
	}
	if len(keys) == 0 {
		return nil, errors.New("IMGPROXY_KEYS contains no valid keys")
	}
	return keys, nil
}
