package driver

import (
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"time"

	internalvnc "github.com/sensepost/gowitness/internal/vnc"
	"github.com/sensepost/gowitness/pkg/models"
	"github.com/sensepost/gowitness/pkg/runner"
)

// VNC is a driver that screenshots VNC servers using the RFB protocol.
//
// When ForceNoAuth is enabled (the default), the driver attempts the
// CVE-2006-2369 style authentication bypass against vulnerable RealVNC
// servers by sending RFB security type 1 (None) regardless of what the
// server advertised. Patched servers will close the connection.
type VNC struct {
	options runner.Options
	log     *slog.Logger
}

// NewVNC returns a new VNC driver.
func NewVNC(logger *slog.Logger, opts runner.Options) (*VNC, error) {
	return &VNC{options: opts, log: logger}, nil
}

// Witness opens an RFB connection to the target, runs the handshake
// (optionally with the auth bypass), requests one full framebuffer update
// and writes it as a screenshot.
func (v *VNC) Witness(target string, run *runner.Runner) (*models.Result, error) {
	v.log.Debug("vnc witness", "target", target)

	parsed, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid vnc url: %w", err)
	}

	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = strconv.Itoa(v.options.VNC.Port)
	}
	addr := net.JoinHostPort(host, port)

	result := &models.Result{
		URL:       target,
		URLScheme: "vnc",
		ProbedAt:  time.Now(),
	}

	timeout := time.Duration(v.options.Scan.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}

	tcp, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		result.Failed = true
		result.FailedReason = fmt.Sprintf("dial: %s", err)
		return result, nil
	}
	defer tcp.Close()

	// hard deadline for the whole probe so we never block the worker
	_ = tcp.SetDeadline(time.Now().Add(timeout))

	msgCh := make(chan internalvnc.ServerMessage, 16)
	cfg := &internalvnc.ClientConfig{
		Auth: []internalvnc.ClientAuth{
			new(internalvnc.ClientAuthNone),
		},
		Exclusive:       false,
		ForceNoAuth:     v.options.VNC.ForceNoAuth,
		ServerMessageCh: msgCh,
	}

	conn, err := internalvnc.Client(tcp, cfg)
	if err != nil {
		result.Failed = true
		result.FailedReason = fmt.Sprintf("rfb handshake: %s", err)
		return result, nil
	}
	defer conn.Close()

	v.log.Debug("vnc connected",
		"target", target,
		"desktop", conn.DesktopName,
		"width", conn.FrameBufferWidth, "height", conn.FrameBufferHeight,
	)

	if conn.FrameBufferWidth == 0 || conn.FrameBufferHeight == 0 {
		result.Failed = true
		result.FailedReason = "framebuffer has zero dimensions"
		return result, nil
	}

	// We only ask for raw pixels — that lets us build the image without
	// having to implement CopyRect/Hextile/etc. Including the RawEncoding
	// in SetEncodings is just to be explicit; servers always support it.
	if err := conn.SetEncodings([]internalvnc.Encoding{new(internalvnc.RawEncoding)}); err != nil {
		result.Failed = true
		result.FailedReason = fmt.Sprintf("set encodings: %s", err)
		return result, nil
	}

	if err := conn.FramebufferUpdateRequest(false, 0, 0, conn.FrameBufferWidth, conn.FrameBufferHeight); err != nil {
		result.Failed = true
		result.FailedReason = fmt.Sprintf("framebuffer request: %s", err)
		return result, nil
	}

	img := image.NewRGBA(image.Rect(0, 0, int(conn.FrameBufferWidth), int(conn.FrameBufferHeight)))

	settle := time.Duration(v.options.VNC.SettleTime) * time.Second
	if settle <= 0 {
		settle = 2 * time.Second
	}

	// drain at least one FramebufferUpdate, then wait `settle` for any
	// follow-ups before encoding the image.
	gotInitial := false
	deadline := time.Now().Add(timeout)
collect:
	for {
		var waitFor time.Duration
		if gotInitial {
			waitFor = settle
		} else {
			waitFor = timeout
		}
		if remaining := time.Until(deadline); remaining < waitFor {
			waitFor = remaining
		}
		if waitFor <= 0 {
			break collect
		}

		select {
		case msg, ok := <-msgCh:
			if !ok {
				break collect
			}
			fb, isFB := msg.(*internalvnc.FramebufferUpdateMessage)
			if !isFB {
				continue
			}
			for _, rect := range fb.Rectangles {
				paintRectangle(img, rect)
			}
			gotInitial = true

			// keep asking for incremental updates so that lazy servers send
			// us the actual desktop content rather than a single empty rect.
			_ = conn.FramebufferUpdateRequest(true, 0, 0, conn.FrameBufferWidth, conn.FrameBufferHeight)

		case <-time.After(waitFor):
			break collect
		}
	}

	if !gotInitial {
		result.Failed = true
		result.FailedReason = "no framebuffer update received"
		return result, nil
	}

	encoded, err := encodeImage(img, v.options)
	if err != nil {
		return nil, err
	}

	if v.options.Scan.ScreenshotToWriter {
		result.Screenshot = base64.StdEncoding.EncodeToString(encoded)
	}

	if err := finalizeScreenshot(result, target, encoded, img, v.options); err != nil {
		return nil, err
	}

	// Surface useful metadata in fields the existing UI already understands.
	result.Title = conn.DesktopName
	result.FinalURL = target
	result.ResponseCode = 200
	result.ResponseReason = "OK"
	result.Protocol = fmt.Sprintf("rfb/%dx%d", conn.FrameBufferWidth, conn.FrameBufferHeight)

	return result, nil
}

func (v *VNC) Close() {}

// paintRectangle copies a Raw-encoded rectangle into an RGBA image.
// Non-Raw encodings are silently skipped; we requested Raw only.
func paintRectangle(img *image.RGBA, rect internalvnc.Rectangle) {
	raw, ok := rect.Enc.(*internalvnc.RawEncoding)
	if !ok || raw == nil {
		return
	}
	width := int(rect.Width)
	height := int(rect.Height)
	if width == 0 || height == 0 {
		return
	}
	if len(raw.Colors) != width*height {
		return
	}
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			c := raw.Colors[y*width+x]
			img.Set(int(rect.X)+x, int(rect.Y)+y, color.RGBA{
				R: uint8(c.R),
				G: uint8(c.G),
				B: uint8(c.B),
				A: 0xff,
			})
		}
	}
}

// compile-time interface check
var _ runner.Driver = (*VNC)(nil)
