package driver

import (
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	stdlog "log"
	"log/slog"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	grdpcore "github.com/tomatome/grdp/core"
	"github.com/tomatome/grdp/glog"
	"github.com/tomatome/grdp/protocol/nla"
	"github.com/tomatome/grdp/protocol/pdu"
	"github.com/tomatome/grdp/protocol/sec"
	"github.com/tomatome/grdp/protocol/t125"
	"github.com/tomatome/grdp/protocol/tpkt"
	"github.com/tomatome/grdp/protocol/x224"

	"github.com/cmprmsd/gowitness/pkg/models"
	"github.com/cmprmsd/gowitness/pkg/runner"
)

const (
	rdpDefaultWidth  = 1280
	rdpDefaultHeight = 800
)

// grdpLogSink captures grdp's last package-global error message so we can
// attach it to the FailedReason of the result. grdp uses a single shared
// logger; under any concurrency the latest error wins, which is good
// enough as a hint - the actual structured reason still goes to slog.
var grdpLogSink atomic.Value // string

// grdpLogWriter is an io.Writer hooked up to grdp's *log.Logger. Each
// glog.Error/.Warn call writes one line; we forward it to slog.Debug
// (so -D users see grdp's own diagnostics) and remember the last
// message so the witness can include it in FailedReason.
type grdpLogWriter struct{}

func (grdpLogWriter) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	if msg != "" {
		grdpLogSink.Store(msg)
		slog.Default().Debug("grdp", "msg", msg)
	}
	return len(p), nil
}

func init() {
	// Route grdp's package-global logger through slog at debug level so
	// the user can see structured diagnostics on -D. Keep level at ERROR
	// to avoid the trace/debug spam that grdp emits during a normal
	// connection.
	glog.SetLogger(stdlog.New(grdpLogWriter{}, "", 0))
	glog.SetLevel(glog.ERROR)
}

// RDP is a driver that screenshots the login screen of an RDP server.
//
// X.224 negotiation advertises Standard RDP and SSL/TLS so the server
// can pick whichever it allows; grdp transparently upgrades the
// connection to TLS when SSL is selected. NLA (HYBRID / HYBRID_EX) is
// out of scope - those servers reject negotiation and the result is
// marked failed with an actionable hint.
type RDP struct {
	options runner.Options
	log     *slog.Logger
}

// NewRDP returns a new RDP driver.
func NewRDP(logger *slog.Logger, opts runner.Options) (*RDP, error) {
	return &RDP{options: opts, log: logger}, nil
}

// Witness opens an RDP connection at Standard RDP security level, captures
// the bitmap updates that comprise the login screen, encodes the result as
// a screenshot.
func (r *RDP) Witness(target string, run *runner.Runner) (*models.Result, error) {
	r.log.Debug("rdp witness", "target", target)

	parsed, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid rdp url: %w", err)
	}

	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = strconv.Itoa(r.options.RDP.Port)
	}
	addr := net.JoinHostPort(host, port)

	// Credentials may be provided via the URL's userinfo or via CLI flags.
	// URL credentials take precedence. They are NEVER persisted to the
	// result -- we strip the userinfo from the URL before saving.
	username := r.options.RDP.Username
	password := r.options.RDP.Password
	domain := r.options.RDP.Domain
	if parsed.User != nil {
		if u := parsed.User.Username(); u != "" {
			username = u
		}
		if p, ok := parsed.User.Password(); ok {
			password = p
		}
	}

	sanitizedURL := sanitizeRDPURL(parsed)

	result := &models.Result{
		URL:       sanitizedURL,
		URLScheme: "rdp",
		ProbedAt:  time.Now(),
	}

	timeout := time.Duration(r.options.Scan.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	settle := time.Duration(r.options.RDP.SettleTime) * time.Second
	if settle <= 0 {
		settle = 5 * time.Second
	}

	// Reset the package-global grdp log sink for this attempt so any
	// prior error message doesn't get attributed to this scan.
	grdpLogSink.Store("")

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		result.Failed = true
		result.FailedReason = fmt.Sprintf("dial: %s", err)
		// Sentinel response code keeps the row from being dropped by
		// runner.go's "status code was 0" filter so the operator sees
		// the failure (and reason) in the gallery / writers.
		result.ResponseCode = 1
		r.log.Warn("rdp scan failed", "target", target, "reason", result.FailedReason)
		return result, nil
	}
	// best-effort hard deadline so a stalled server can't block the worker
	_ = conn.SetDeadline(time.Now().Add(timeout))

	width := rdpDefaultWidth
	height := rdpDefaultHeight

	// Build the standard grdp protocol stack.
	pktLayer := tpkt.New(grdpcore.NewSocketLayer(conn), nla.NewNTLMv2(domain, username, password))
	x224Layer := x224.New(pktLayer)
	mcs := t125.NewMCSClient(x224Layer)
	secLayer := sec.NewClient(mcs)
	pduLayer := pdu.NewClient(secLayer)

	mcs.SetClientCoreData(uint16(width), uint16(height))
	secLayer.SetUser(username)
	secLayer.SetPwd(password)
	secLayer.SetDomain(domain)

	pktLayer.SetFastPathListener(secLayer)
	secLayer.SetFastPathListener(pduLayer)
	secLayer.SetChannelSender(mcs)

	// Advertise plain RDP and SSL/TLS. grdp's x224 layer transparently
	// upgrades to TLS (with InsecureSkipVerify) when the server selects
	// PROTOCOL_SSL, which Windows hosts default to. We deliberately do
	// NOT advertise PROTOCOL_HYBRID (NLA) - the auth dance is out of
	// scope for unauth recon, and HYBRID_REQUIRED servers will surface
	// as code 5/6 with an actionable hint below.
	x224Layer.SetRequestedProtocol(x224.PROTOCOL_RDP | x224.PROTOCOL_SSL)

	screen := image.NewRGBA(image.Rect(0, 0, width, height))
	var (
		paintMu     sync.Mutex
		lastUpdate  atomic.Int64 // unix-nano timestamp of the most recent bitmap update
		gotUpdate   atomic.Bool
		gotReady    atomic.Bool // true once the PDU layer reports "ready" (i.e. X.224 + MCS + capabilities done)
		closeOnce   sync.Once
		closeReason atomic.Value // string
		done        = make(chan struct{})
	)
	signalDone := func(reason string) {
		closeOnce.Do(func() {
			closeReason.Store(reason)
			close(done)
		})
	}

	pduLayer.On("error", func(e error) {
		r.log.Debug("rdp protocol error", "target", target, "err", e)
		signalDone(fmt.Sprintf("protocol: %s", e))
	}).On("close", func() {
		signalDone("connection closed")
	}).On("ready", func() {
		gotReady.Store(true)
	}).On("update", func(rectangles []pdu.BitmapData) {
		paintMu.Lock()
		defer paintMu.Unlock()
		for _, rect := range rectangles {
			paintBitmap(screen, &rect)
		}
		gotUpdate.Store(true)
		lastUpdate.Store(time.Now().UnixNano())
	})

	if err := x224Layer.Connect(); err != nil {
		_ = conn.Close()
		result.Failed = true
		result.FailedReason = fmt.Sprintf("x224 connect: %s", err)
		result.ResponseCode = 1
		r.log.Warn("rdp scan failed", "target", target, "reason", result.FailedReason)
		return result, nil
	}

	// Wait for the first update or timeout, then keep waiting until updates
	// have stopped for `settle` seconds (login screens animate briefly when
	// they first paint).
	deadline := time.Now().Add(timeout)
waitLoop:
	for {
		select {
		case <-done:
			break waitLoop
		default:
		}
		if time.Now().After(deadline) {
			break
		}
		if gotUpdate.Load() {
			last := time.Unix(0, lastUpdate.Load())
			if time.Since(last) >= settle {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Tear down the connection - we have what we need.
	_ = pktLayer.Close()
	_ = conn.Close()

	if !gotUpdate.Load() {
		reason := "no bitmap updates received"
		if rv := closeReason.Load(); rv != nil {
			if s, ok := rv.(string); ok && s != "" {
				reason = s
			}
		}

		// Translate the grdp-captured X.224 negotiation failure code
		// into something the operator can act on. See MS-RDPBCGR
		// 2.2.1.2.2 for the full enum.
		hint, _ := grdpLogSink.Load().(string)
		if !gotReady.Load() {
			if code, ok := extractX224NegCode(hint); ok {
				switch code {
				case 1: // SSL_REQUIRED_BY_SERVER - shouldn't trigger now (we advertise SSL)
					reason = "server requires SSL/TLS only; client advertised it but the negotiation still failed"
				case 2: // SSL_NOT_ALLOWED_BY_SERVER
					reason = "server requires plain RDP and rejected SSL/TLS"
				case 3: // SSL_CERT_NOT_ON_SERVER
					reason = "server cannot present an SSL certificate"
				case 4: // INCONSISTENT_FLAGS
					reason = "x224 negotiation: inconsistent flags"
				case 5: // HYBRID_REQUIRED_BY_SERVER
					reason = "server requires NLA (HYBRID); this driver cannot complete the CredSSP handshake"
				case 6: // SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER
					reason = "server requires NLA over SSL (HYBRID_EX); this driver cannot complete the CredSSP handshake"
				default:
					reason = fmt.Sprintf("x224 negotiation rejected (code %d)", code)
				}
			} else if strings.Contains(reason, "use of closed network connection") {
				reason = "x224 negotiation rejected before handshake completed (server likely requires NLA)"
			}
		}
		if hint != "" {
			reason = fmt.Sprintf("%s [grdp: %s]", reason, hint)
		}

		result.Failed = true
		result.FailedReason = reason
		result.ResponseCode = 1
		r.log.Warn("rdp scan failed", "target", target, "reason", reason)
		return result, nil
	}

	paintMu.Lock()
	encoded, err := encodeImage(screen, r.options)
	paintMu.Unlock()
	if err != nil {
		return nil, err
	}

	if r.options.Scan.ScreenshotToWriter {
		result.Screenshot = base64.StdEncoding.EncodeToString(encoded)
	}

	if err := finalizeScreenshot(result, sanitizedURL, encoded, screen, r.options); err != nil {
		return nil, err
	}

	result.Title = fmt.Sprintf("RDP %s", host)
	result.FinalURL = sanitizedURL
	result.ResponseCode = 200
	result.ResponseReason = "OK"
	result.Protocol = fmt.Sprintf("rdp/%dx%d", width, height)

	return result, nil
}

func (r *RDP) Close() {}

// sanitizeRDPURL strips userinfo (credentials) from an rdp:// URL so creds
// are never persisted to the database or exports.
func sanitizeRDPURL(u *url.URL) string {
	clone := *u
	clone.User = nil
	return clone.String()
}

// x224NegCodeRe matches the numeric error code grdp logs on a
// TYPE_RDP_NEG_FAILURE message - e.g.
// "NODE_RDP_PROTOCOL_X224_NEG_FAILURE with code: 5,see ...".
var x224NegCodeRe = regexp.MustCompile(`code:\s*(\d+)`)

func extractX224NegCode(s string) (int, bool) {
	m := x224NegCodeRe.FindStringSubmatch(s)
	if len(m) != 2 {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return n, true
}

// paintBitmap copies a single RDP BitmapData rectangle into an RGBA image.
// The rectangle may be RDP6 RLE compressed; in that case we decompress
// first using grdp's reference implementation. Pixel formats supported are
// 15 / 16 (RGB565) / 24 / 32-bpp.
func paintBitmap(dst *image.RGBA, b *pdu.BitmapData) {
	bytesPerPixel := bppToBytes(b.BitsPerPixel)
	if bytesPerPixel == 0 {
		return
	}

	data := b.BitmapDataStream
	if b.IsCompress() {
		data = grdpcore.Decompress(b.BitmapDataStream, int(b.Width), int(b.Height), bytesPerPixel)
	}

	width := int(b.Width)
	height := int(b.Height)
	expected := width * height * bytesPerPixel
	if len(data) < expected {
		return
	}

	rect := image.NewRGBA(image.Rect(0, 0, width, height))
	idx := 0
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			r, g, bl, a := bitmapPixel(bytesPerPixel, idx, data)
			rect.Set(x, y, color.RGBA{R: r, G: g, B: bl, A: a})
			idx += bytesPerPixel
		}
	}

	dstRect := dst.Bounds().Intersect(image.Rect(int(b.DestLeft), int(b.DestTop),
		int(b.DestLeft)+width, int(b.DestTop)+height))
	if dstRect.Empty() {
		return
	}
	draw.Draw(dst, dstRect, rect, image.Point{}, draw.Src)
}

func bppToBytes(bpp uint16) int {
	switch bpp {
	case 15, 16:
		return 2
	case 24:
		return 3
	case 32:
		return 4
	}
	return 0
}

// bitmapPixel mirrors the example in the grdp library: 16bpp uses RGB565,
// 24/32bpp uses BGRA byte order on the wire.
func bitmapPixel(bytesPerPixel, i int, data []byte) (r, g, b, a uint8) {
	a = 0xff
	switch bytesPerPixel {
	case 2:
		v := grdpcore.Uint16BE(data[i], data[i+1])
		r, g, b = grdpcore.RGB565ToRGB(v)
	case 3, 4:
		// Wire order is B, G, R, [A]
		b, g, r = data[i], data[i+1], data[i+2]
	}
	return
}

// compile-time interface check
var _ runner.Driver = (*RDP)(nil)
