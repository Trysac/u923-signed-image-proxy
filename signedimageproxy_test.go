package signedimageproxy_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Trysac/u923-signed-image-proxy"
)

var testKey1 = []byte("0123456789abcdef")
var testKey2 = []byte("fedcba9876543210")

func makeTestPNG(w, h int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	// Draw a coloured centre vs border so centre-cropping is verifiable.
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			if x >= w/4 && x < 3*w/4 && y >= h/4 && y < 3*h/4 {
				img.Set(x, y, color.RGBA{R: 200, G: 20, B: 40, A: 255})
			} else {
				img.Set(x, y, color.RGBA{R: 10, G: 20, B: 200, A: 255})
			}
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func makeTestGIF(w, h int) []byte {
	palette := []color.Color{color.Black, color.White}
	paletted := image.NewPaletted(image.Rect(0, 0, w, h), palette)
	var buf bytes.Buffer
	if err := gif.Encode(&buf, paletted, nil); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// makePNGHeaderOnly constructs a valid minimal PNG file header (signature + IHDR)
// declaring width x height without needing to allocate 10000x10000 pixels.
func makePNGHeaderOnly(width, height uint32) []byte {
	var buf bytes.Buffer
	buf.Write([]byte("\x89PNG\r\n\x1a\n"))
	var ihdr [13]byte
	binary.BigEndian.PutUint32(ihdr[0:4], width)
	binary.BigEndian.PutUint32(ihdr[4:8], height)
	ihdr[8] = 8 // bit depth
	ihdr[9] = 2 // color type RGB
	_ = binary.Write(&buf, binary.BigEndian, uint32(13))
	buf.WriteString("IHDR")
	buf.Write(ihdr[:])
	crc := crc32.NewIEEE()
	crc.Write([]byte("IHDR"))
	crc.Write(ihdr[:])
	_ = binary.Write(&buf, binary.BigEndian, crc.Sum32())
	return buf.Bytes()
}

type testEnv struct {
	upstream   *httptest.Server
	proxy      *signedimageproxy.Proxy
	dialCount  atomic.Int64
	fetchCount atomic.Int64
	lastDialed atomic.Value
	clockMu    sync.Mutex
	now        time.Time
	eventsMu   sync.Mutex
	events     []signedimageproxy.Event
}

func newTestEnv(t *testing.T, handler http.HandlerFunc, mutateCfg func(*signedimageproxy.Config)) *testEnv {
	t.Helper()
	env := &testEnv{
		now: time.Unix(1700000000, 0),
	}
	env.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env.fetchCount.Add(1)
		handler(w, r)
	}))
	t.Cleanup(env.upstream.Close)

	publicIP := netip.MustParseAddr("93.184.216.34")
	upstreamAddr := env.upstream.Listener.Addr().String()

	cfg := signedimageproxy.Config{
		Keys: [][]byte{testKey1, testKey2},
		Resolver: func(ctx context.Context, host string) ([]netip.Addr, error) {
			if host == "img.example.test" {
				return []netip.Addr{publicIP}, nil
			}
			return nil, errors.New("unknown host")
		},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			env.dialCount.Add(1)
			env.lastDialed.Store(addr)
			// Verify the proxy dials the resolved IP literal, not the hostname.
			h, _, err := net.SplitHostPort(addr)
			if err != nil || h != "93.184.216.34" {
				return nil, fmt.Errorf("unexpected dial target %q", addr)
			}
			var d net.Dialer
			return d.DialContext(ctx, network, upstreamAddr)
		},
		Clock: func() time.Time {
			env.clockMu.Lock()
			defer env.clockMu.Unlock()
			return env.now
		},
		OnEvent: func(ev signedimageproxy.Event) {
			env.eventsMu.Lock()
			env.events = append(env.events, ev)
			env.eventsMu.Unlock()
		},
	}
	if mutateCfg != nil {
		mutateCfg(&cfg)
	}
	p, err := signedimageproxy.New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	env.proxy = p
	return env
}

// Acceptance Item 1: Exact Sign vector.
func TestSignVector(t *testing.T) {
	got := signedimageproxy.Sign([]byte("test-key-1"), "w:100,h:50,fit:cover", "https://img.example.test/cat.png")
	want := "/chz44SBvXwmcsv3ZrbIy_ZpFzFG_KWU_68Pfcj7z8IY/w:100,h:50,fit:cover/aHR0cHM6Ly9pbWcuZXhhbXBsZS50ZXN0L2NhdC5wbmc"
	if got != want {
		t.Fatalf("Sign() = %q, want %q", got, want)
	}
}

// Acceptance Item 2: Image transforms (fill, contain, cover) and format conversion.
func TestTransformsAndFormats(t *testing.T) {
	srcPNG := makeTestPNG(400, 200)
	srcGIF := makeTestGIF(200, 100)

	env := newTestEnv(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "img.example.test" {
			t.Errorf("expected Host header img.example.test, got %q", r.Host)
		}
		if strings.HasSuffix(r.URL.Path, ".gif") {
			w.Header().Set("Content-Type", "image/gif")
			_, _ = w.Write(srcGIF)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(srcPNG)
	}, nil)

	tests := []struct {
		name            string
		opts            string
		src             string
		wantW           int
		wantH           int
		wantContentType string
		checkCenterRed  bool
	}{
		{
			name:            "fill 100x50",
			opts:            "w:100,h:50,fit:fill",
			src:             "http://img.example.test/cat.png",
			wantW:           100,
			wantH:           50,
			wantContentType: "image/png",
		},
		{
			name:            "contain 100x100 from 400x200 yields 100x50",
			opts:            "w:100,h:100,fit:contain",
			src:             "http://img.example.test/cat.png",
			wantW:           100,
			wantH:           50,
			wantContentType: "image/png",
		},
		{
			name:            "cover 100x100 cropped around centre",
			opts:            "w:100,h:100,fit:cover",
			src:             "http://img.example.test/cat.png",
			wantW:           100,
			wantH:           100,
			wantContentType: "image/png",
			checkCenterRed:  true,
		},
		{
			name:            "fmt:jpeg returns image/jpeg",
			opts:            "w:100,h:50,fmt:jpeg,q:80",
			src:             "http://img.example.test/cat.png",
			wantW:           100,
			wantH:           50,
			wantContentType: "image/jpeg",
		},
		{
			name:            "missing h computed from w",
			opts:            "w:200",
			src:             "http://img.example.test/cat.png",
			wantW:           200,
			wantH:           100,
			wantContentType: "image/png",
		},
		{
			name:            "missing w computed from h",
			opts:            "h:50",
			src:             "http://img.example.test/cat.png",
			wantW:           100,
			wantH:           50,
			wantContentType: "image/png",
		},
		{
			name:            "gif source defaults to png output",
			opts:            "w:50,h:25",
			src:             "http://img.example.test/anim.gif",
			wantW:           50,
			wantH:           25,
			wantContentType: "image/png",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := signedimageproxy.Sign(testKey1, tc.opts, tc.src)
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			env.proxy.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d (%s), want 200", rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("Content-Type"); got != tc.wantContentType {
				t.Fatalf("Content-Type = %q, want %q", got, tc.wantContentType)
			}
			if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Fatalf("X-Content-Type-Options = %q, want nosniff", got)
			}
			if got := rec.Header().Get("Content-Security-Policy"); got != "default-src 'none'" {
				t.Fatalf("Content-Security-Policy = %q, want default-src 'none'", got)
			}

			var img image.Image
			var err error
			if tc.wantContentType == "image/jpeg" {
				img, err = jpeg.Decode(bytes.NewReader(rec.Body.Bytes()))
			} else {
				img, err = png.Decode(bytes.NewReader(rec.Body.Bytes()))
			}
			if err != nil {
				t.Fatalf("decode output failed: %v", err)
			}
			if img.Bounds().Dx() != tc.wantW || img.Bounds().Dy() != tc.wantH {
				t.Fatalf("dimensions = %dx%d, want %dx%d", img.Bounds().Dx(), img.Bounds().Dy(), tc.wantW, tc.wantH)
			}
			if tc.checkCenterRed {
				r, _, b, _ := img.At(50, 50).RGBA()
				if r <= b {
					t.Fatalf("expected red centre pixel after cover crop, got R=%d B=%d", r, b)
				}
			}
		})
	}
}

// Acceptance Item 3: Tampered signatures, missing segments, key rotation, and expiration.
func TestSignaturesAndExpiry(t *testing.T) {
	srcPNG := makeTestPNG(40, 40)
	env := newTestEnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(srcPNG)
	}, nil)

	validPath := signedimageproxy.Sign(testKey1, "w:20,h:20", "http://img.example.test/cat.png")
	tamperedPath := strings.Replace(validPath, "w:20,h:20", "w:30,h:20", 1)

	for _, badPath := range []string{
		tamperedPath,
		"/w:20,h:20/aHR0cDovL2ltZy5leGFtcGxlLnRlc3QvY2F0LnBuZw",
		"/",
		"/short/w:20/aHR0cDovL2ltZy5leGFtcGxlLnRlc3QvY2F0LnBuZw",
		"/" + strings.Repeat("a", 43) + "/w:20/aHR0cDovL2ltZy5leGFtcGxlLnRlc3QvY2F0LnBuZw/extra",
	} {
		req := httptest.NewRequest(http.MethodGet, badPath, nil)
		rec := httptest.NewRecorder()
		env.proxy.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden || rec.Body.String() != "invalid signature" {
			t.Fatalf("path %q: status=%d body=%q, want 403 'invalid signature'", badPath, rec.Code, rec.Body.String())
		}
	}

	// Secondary key in Config.Keys also verifies.
	secondarySigned := signedimageproxy.Sign(testKey2, "w:20,h:20", "http://img.example.test/cat.png")
	req2 := httptest.NewRequest(http.MethodGet, secondarySigned, nil)
	rec2 := httptest.NewRecorder()
	env.proxy.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("secondary key verification failed: status=%d", rec2.Code)
	}

	// Expired URL with exp:1700000000 when clock is past that time.
	env.clockMu.Lock()
	env.now = time.Unix(1700000001, 0)
	env.clockMu.Unlock()

	expPath := signedimageproxy.Sign(testKey1, "w:20,h:20,exp:1700000000", "http://img.example.test/cat.png")
	reqExp := httptest.NewRequest(http.MethodGet, expPath, nil)
	recExp := httptest.NewRecorder()
	env.proxy.ServeHTTP(recExp, reqExp)
	if recExp.Code != http.StatusForbidden || recExp.Body.String() != "expired" {
		t.Fatalf("expired URL: status=%d body=%q, want 403 'expired'", recExp.Code, recExp.Body.String())
	}
}

// Acceptance Item 4: ETag format, Cache-Control, If-None-Match 304, and cache hits.
func TestETagAndCaching(t *testing.T) {
	srcPNG := makeTestPNG(100, 100)
	env := newTestEnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(srcPNG)
	}, nil)

	path := signedimageproxy.Sign(testKey1, "w:50,h:50", "http://img.example.test/cat.png")

	// First request: cache miss.
	req1 := httptest.NewRequest(http.MethodGet, path, nil)
	rec1 := httptest.NewRecorder()
	env.proxy.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("req1 status = %d, want 200", rec1.Code)
	}
	etag := rec1.Header().Get("ETag")
	matched, _ := regexp.MatchString(`^"[0-9a-f]{32}"$`, etag)
	if !matched {
		t.Fatalf("ETag = %q, want \"<32 hex>\"", etag)
	}
	if cc := rec1.Header().Get("Cache-Control"); cc != "public, max-age=86400" {
		t.Fatalf("Cache-Control = %q, want 'public, max-age=86400'", cc)
	}
	if env.fetchCount.Load() != 1 {
		t.Fatalf("fetchCount = %d, want 1", env.fetchCount.Load())
	}

	// Second identical request: served from cache, source fetched once.
	req2 := httptest.NewRequest(http.MethodGet, path, nil)
	rec2 := httptest.NewRecorder()
	env.proxy.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK || !bytes.Equal(rec1.Body.Bytes(), rec2.Body.Bytes()) {
		t.Fatalf("req2 failed or body mismatch")
	}
	if env.fetchCount.Load() != 1 {
		t.Fatalf("fetchCount after cache hit = %d, want 1", env.fetchCount.Load())
	}

	// Third request with If-None-Match: returns 304 with empty body.
	req3 := httptest.NewRequest(http.MethodGet, path, nil)
	req3.Header.Set("If-None-Match", etag)
	rec3 := httptest.NewRecorder()
	env.proxy.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusNotModified || rec3.Body.Len() != 0 {
		t.Fatalf("If-None-Match status=%d bodyLen=%d, want 304 and 0", rec3.Code, rec3.Body.Len())
	}

	// Wildcard If-None-Match '*'.
	req4 := httptest.NewRequest(http.MethodGet, path, nil)
	req4.Header.Set("If-None-Match", "*")
	rec4 := httptest.NewRecorder()
	env.proxy.ServeHTTP(rec4, req4)
	if rec4.Code != http.StatusNotModified {
		t.Fatalf("If-None-Match * status=%d, want 304", rec4.Code)
	}
}

// Acceptance Item 5: SSRF protection for private/reserved addresses, schemes, and redirects.
func TestSSRFProtection(t *testing.T) {
	forbiddenIPs := []string{
		"127.0.0.1",
		"10.1.2.3",
		"169.254.169.254",
		"::1",
		"fc00::1",
		"::ffff:10.0.0.1",
		"100.64.0.1",
		"0.0.0.0",
		"192.0.2.1",
		"198.18.0.1",
		"255.255.255.255",
		"2001:db8::1",
	}

	for _, rawIP := range forbiddenIPs {
		t.Run("ip_"+rawIP, func(t *testing.T) {
			var dialCalled atomic.Bool
			p, err := signedimageproxy.New(signedimageproxy.Config{
				Keys:         [][]byte{testKey1},
				AllowPrivate: false,
				Resolver: func(ctx context.Context, host string) ([]netip.Addr, error) {
					return []netip.Addr{netip.MustParseAddr(rawIP)}, nil
				},
				Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
					dialCalled.Store(true)
					return nil, errors.New("should not dial")
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			path := signedimageproxy.Sign(testKey1, "w:10,h:10", "http://internal.example.test/img.png")
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden || rec.Body.String() != "forbidden address" {
				t.Fatalf("IP %s: status=%d body=%q, want 403 'forbidden address'", rawIP, rec.Code, rec.Body.String())
			}
			if dialCalled.Load() {
				t.Fatalf("IP %s: dialer was called on forbidden address", rawIP)
			}
		})
	}

	// Invalid source URLs: file:///etc/passwd, userinfo, disallowed host.
	env := newTestEnv(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect-metadata" {
			http.Redirect(w, r, "http://169.254.169.254/", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}, func(cfg *signedimageproxy.Config) {
		cfg.AllowedHosts = []string{"img.example.test"}
	})

	for _, badSrc := range []string{
		"file:///etc/passwd",
		"ftp://img.example.test/a.png",
		"http://user:pass@img.example.test/a.png",
		"http://other.example.test/a.png",
	} {
		path := signedimageproxy.Sign(testKey1, "w:10,h:10", badSrc)
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		env.proxy.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest || rec.Body.String() != "invalid source" {
			t.Fatalf("source %q: status=%d body=%q, want 400 'invalid source'", badSrc, rec.Code, rec.Body.String())
		}
	}

	// Redirect to http://169.254.169.254/ returns 403.
	redirPath := signedimageproxy.Sign(testKey1, "w:10,h:10", "http://img.example.test/redirect-metadata")
	reqRedir := httptest.NewRequest(http.MethodGet, redirPath, nil)
	recRedir := httptest.NewRecorder()
	env.proxy.ServeHTTP(recRedir, reqRedir)
	if recRedir.Code != http.StatusForbidden {
		t.Fatalf("redirect to 169.254.169.254: status=%d, want 403", recRedir.Code)
	}
}

// Acceptance Item 6: Source byte limits (20_971_520 vs 20_971_521), pixel cap (10000x10000), Content-Type.
func TestSizeAndMediaLimits(t *testing.T) {
	env := newTestEnv(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/too-large-bytes":
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(make([]byte, 20_971_521))
		case "/exact-limit-bytes":
			w.Header().Set("Content-Type", "image/png")
			// Valid PNG padded to exactly 20_971_520 bytes.
			smallPNG := makeTestPNG(10, 10)
			_, _ = w.Write(smallPNG)
			padding := make([]byte, 20_971_520-len(smallPNG))
			_, _ = w.Write(padding)
		case "/bomb-10000x10000":
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(makePNGHeaderOnly(10000, 10000))
		case "/html":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html></html>"))
		}
	}, nil)

	// 20_971_521 bytes -> 502 "source too large".
	p1 := signedimageproxy.Sign(testKey1, "w:10,h:10", "http://img.example.test/too-large-bytes")
	rec1 := httptest.NewRecorder()
	env.proxy.ServeHTTP(rec1, httptest.NewRequest(http.MethodGet, p1, nil))
	if rec1.Code != http.StatusBadGateway || rec1.Body.String() != "source too large" {
		t.Fatalf("20_971_521 bytes: status=%d body=%q, want 502 'source too large'", rec1.Code, rec1.Body.String())
	}

	// 20_971_520 bytes -> read and decoded.
	p2 := signedimageproxy.Sign(testKey1, "w:10,h:10", "http://img.example.test/exact-limit-bytes")
	rec2 := httptest.NewRecorder()
	env.proxy.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, p2, nil))
	if rec2.Code != http.StatusOK {
		t.Fatalf("20_971_520 bytes: status=%d body=%q, want 200", rec2.Code, rec2.Body.String())
	}

	// 10000x10000 PNG header -> 422 "image too large".
	p3 := signedimageproxy.Sign(testKey1, "w:10,h:10", "http://img.example.test/bomb-10000x10000")
	rec3 := httptest.NewRecorder()
	env.proxy.ServeHTTP(rec3, httptest.NewRequest(http.MethodGet, p3, nil))
	if rec3.Code != http.StatusUnprocessableEntity || rec3.Body.String() != "image too large" {
		t.Fatalf("10000x10000 bomb: status=%d body=%q, want 422 'image too large'", rec3.Code, rec3.Body.String())
	}

	// Content-Type "text/html" -> 415.
	p4 := signedimageproxy.Sign(testKey1, "w:10,h:10", "http://img.example.test/html")
	rec4 := httptest.NewRecorder()
	env.proxy.ServeHTTP(rec4, httptest.NewRequest(http.MethodGet, p4, nil))
	if rec4.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("text/html: status=%d, want 415", rec4.Code)
	}
}

// Acceptance Item 7: Single-flight 10 concurrent requests, caller cancellation, and tiny MaxCacheBytes.
func TestSingleFlightAndTinyCache(t *testing.T) {
	srcPNG := makeTestPNG(80, 80)
	releaseUpstream := make(chan struct{})
	fetchStarted := make(chan struct{})
	var startOnce sync.Once

	env := newTestEnv(t, func(w http.ResponseWriter, r *http.Request) {
		startOnce.Do(func() { close(fetchStarted) })
		<-releaseUpstream
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(srcPNG)
	}, nil)

	path := signedimageproxy.Sign(testKey1, "w:40,h:40", "http://img.example.test/concurrent.png")

	const totalCallers = 10
	var wg sync.WaitGroup
	wg.Add(totalCallers)
	statuses := make([]int, totalCallers)

	startTime := time.Now()
	for i := 0; i < totalCallers; i++ {
		go func(idx int) {
			defer wg.Done()
			ctx := context.Background()
			if idx == 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 20*time.Millisecond)
				defer cancel()
			}
			req := httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx)
			rec := httptest.NewRecorder()
			env.proxy.ServeHTTP(rec, req)
			statuses[idx] = rec.Code
		}(i)
	}

	<-fetchStarted
	time.Sleep(40 * time.Millisecond)
	close(releaseUpstream)
	wg.Wait()

	if elapsed := time.Since(startTime); elapsed >= time.Second {
		t.Fatalf("single-flight test took %v, expected < 1s", elapsed)
	}
	if env.fetchCount.Load() != 1 {
		t.Fatalf("fetchCount = %d, want 1 for 10 concurrent requests", env.fetchCount.Load())
	}
	if statuses[0] == http.StatusOK {
		t.Fatalf("cancelled caller 0 received 200, expected cancellation status")
	}
	for i := 1; i < totalCallers; i++ {
		if statuses[i] != http.StatusOK {
			t.Fatalf("caller %d status = %d, want 200", i, statuses[i])
		}
	}

	// With MaxCacheBytes below one result, nothing is cached and every request fetches.
	envTiny := newTestEnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(srcPNG)
	}, func(cfg *signedimageproxy.Config) {
		cfg.MaxCacheBytes = 10 // smaller than any encoded PNG
	})

	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		envTiny.proxy.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("tiny cache req %d status = %d, want 200", i, rec.Code)
		}
	}
	if envTiny.fetchCount.Load() != 3 {
		t.Fatalf("tiny cache fetchCount = %d, want 3", envTiny.fetchCount.Load())
	}
}

func TestOptionsValidationAndLRUEviction(t *testing.T) {
	srcPNG := makeTestPNG(50, 50)
	env := newTestEnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(srcPNG)
	}, func(cfg *signedimageproxy.Config) {
		cfg.MaxOutputSide = 500
		cfg.MaxCacheBytes = 1500 // Holds roughly 1-2 small PNGs, triggering LRU eviction.
	})

	badOptions := []string{
		"fit:contain",
		"w:0,h:50",
		"w:501,h:50",
		"w:50,w:50",
		"w:50,fit:invalid",
		"w:50,fmt:webp",
		"w:50,q:0",
		"w:50,q:101",
		"w:50,unknown:1",
		"w:50,badtoken",
		"w:50,exp:-5",
	}
	for _, opt := range badOptions {
		path := signedimageproxy.Sign(testKey1, opt, "http://img.example.test/a.png")
		rec := httptest.NewRecorder()
		env.proxy.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusBadRequest || rec.Body.String() != "invalid options" {
			t.Fatalf("options %q: status=%d body=%q, want 400 'invalid options'", opt, rec.Code, rec.Body.String())
		}
	}

	// Trigger LRU eviction across multiple distinct keys.
	for i := 1; i <= 5; i++ {
		p := signedimageproxy.Sign(testKey1, fmt.Sprintf("w:%d,h:%d", i*10, i*10), "http://img.example.test/a.png")
		rec := httptest.NewRecorder()
		env.proxy.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("req %d failed: %d", i, rec.Code)
		}
	}
}

func TestConfigErrorsAndCLI(t *testing.T) {
	if _, err := signedimageproxy.New(signedimageproxy.Config{}); !errors.Is(err, signedimageproxy.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for empty keys, got %v", err)
	}
	if _, err := signedimageproxy.New(signedimageproxy.Config{Keys: [][]byte{[]byte("short")}}); !errors.Is(err, signedimageproxy.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for short key, got %v", err)
	}

	// CLI tests.
	t.Setenv("IMGPROXY_KEYS", hex.EncodeToString(testKey1))
	var stdout, stderr bytes.Buffer
	code := signedimageproxy.Run([]string{"sign", "-options", "w:100,h:50,fit:cover", "https://img.example.test/cat.png"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run sign exit=%d stderr=%s", code, stderr.String())
	}
	wantSign := signedimageproxy.Sign(testKey1, "w:100,h:50,fit:cover", "https://img.example.test/cat.png")
	if strings.TrimSpace(stdout.String()) != wantSign {
		t.Fatalf("CLI sign output = %q, want %q", strings.TrimSpace(stdout.String()), wantSign)
	}

	// CLI usage errors.
	if c := signedimageproxy.Run(nil, &stdout, &stderr); c != 2 {
		t.Fatalf("Run(nil) = %d, want 2", c)
	}
	if c := signedimageproxy.Run([]string{"unknown"}, &stdout, &stderr); c != 2 {
		t.Fatalf("Run(unknown) = %d, want 2", c)
	}
	if c := signedimageproxy.Run([]string{"sign"}, &stdout, &stderr); c != 2 {
		t.Fatalf("Run(sign no args) = %d, want 2", c)
	}

	// CLI missing key error.
	t.Setenv("IMGPROXY_KEYS", "")
	if c := signedimageproxy.Run([]string{"sign", "-options", "w:10", "https://img.example.test/a.png"}, &stdout, &stderr); c != 1 {
		t.Fatalf("Run(sign without env key) = %d, want 1", c)
	}
}

func ExampleSign() {
	key := []byte("test-key-1")
	path := signedimageproxy.Sign(key, "w:100,h:50,fit:cover", "https://img.example.test/cat.png")
	fmt.Println(path)
	// Output:
	// /chz44SBvXwmcsv3ZrbIy_ZpFzFG_KWU_68Pfcj7z8IY/w:100,h:50,fit:cover/aHR0cHM6Ly9pbWcuZXhhbXBsZS50ZXN0L2NhdC5wbmc
}
