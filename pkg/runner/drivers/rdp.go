package driver

import (
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"log/slog"
	"net"
	"net/url"
	"strconv"
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

	"github.com/sensepost/gowitness/pkg/models"
	"github.com/sensepost/gowitness/pkg/runner"
)

const (
	rdpDefaultWidth  = 1280
	rdpDefaultHeight = 800
)

func init() {
	// grdp's logger is package-global and noisy by default. Silence it; the
	// driver surfaces its own structured errors via slog.
	glog.SetLevel(glog.NONE)
}

// RDP is a driver that screenshots the login screen of an RDP server using
// Standard RDP security (no NLA/SSL). NLA-protected hosts will fail the
// X.224 handshake and the result is marked as failed.
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

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		result.Failed = true
		result.FailedReason = fmt.Sprintf("dial: %s", err)
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

	// Standard RDP security only: skip TLS/NLA, capture the unencrypted login
	// screen. Modern Windows servers with NLA enforced will fail here, which
	// is reflected as a failed result.
	x224Layer.SetRequestedProtocol(x224.PROTOCOL_RDP)

	screen := image.NewRGBA(image.Rect(0, 0, width, height))
	var (
		paintMu     sync.Mutex
		lastUpdate  atomic.Int64 // unix-nano timestamp of the most recent bitmap update
		gotUpdate   atomic.Bool
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
		result.Failed = true
		result.FailedReason = reason
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
