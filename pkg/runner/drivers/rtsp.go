package driver

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"image"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/sensepost/gowitness/pkg/models"
	"github.com/sensepost/gowitness/pkg/runner"
)

// RTSP is a driver that grabs a single video frame from an RTSP server
// (typically an IP camera) and stores it as a screenshot.
//
// Pure-Go decoders for H.264/H.265 are immature, so the driver shells out
// to ffmpeg for the heavy lifting - the same external-binary pattern
// gowitness already uses for Chrome. ffmpeg covers MJPEG, H.264, H.265,
// MPEG-4 etc. uniformly, handles RTSP-over-TCP and RTSP-over-UDP, and
// applies any URL-embedded credentials transparently.
type RTSP struct {
	options runner.Options
	log     *slog.Logger
	ffmpeg  string // resolved path or empty if not available
}

// NewRTSP returns a new RTSP driver. Missing ffmpeg is a warning, not a
// fatal error - a registered-but-broken driver still surfaces failed
// rtsp:// scans in the gallery so the operator notices the dependency.
func NewRTSP(logger *slog.Logger, opts runner.Options) (*RTSP, error) {
	bin, err := exec.LookPath("ffmpeg")
	if err != nil {
		logger.Warn("ffmpeg not found in PATH; rtsp:// scans will fail until you install it",
			"hint", "apt install ffmpeg / brew install ffmpeg / choco install ffmpeg")
		bin = ""
	}
	return &RTSP{options: opts, log: logger, ffmpeg: bin}, nil
}

// Witness pulls a single I-frame via ffmpeg, decodes it, runs the result
// through the standard screenshot pipeline (perception hash + disk write).
//
// When the URL has no embedded creds and no CLI default is configured,
// the driver walks a small credential ladder (anonymous, then each entry
// of options.RTSP.DefaultCreds in order) until ffmpeg returns a frame.
// The first attempt that yields a frame wins; its credentials are NOT
// persisted to the result.
func (r *RTSP) Witness(target string, run *runner.Runner) (*models.Result, error) {
	r.log.Debug("rtsp witness", "target", target)

	parsed, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid rtsp url: %w", err)
	}

	saveURL := sanitizeRTSPURL(parsed)

	result := &models.Result{
		URL:       saveURL,
		URLScheme: "rtsp",
		ProbedAt:  time.Now(),
	}

	if r.ffmpeg == "" {
		result.Failed = true
		result.FailedReason = "ffmpeg not installed; rtsp scans require it"
		// Sentinel: any non-zero ResponseCode keeps the row from being
		// dropped by runner.go's "status code was 0" filter, so the
		// failure shows up in the gallery / writers as a finding.
		result.ResponseCode = 1
		r.log.Warn("rtsp scan failed", "target", saveURL, "reason", result.FailedReason)
		return result, nil
	}

	timeout := time.Duration(r.options.Scan.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	// Build the ladder of dial URLs to try. Each entry carries a label
	// describing the credentials used so we can persist the winning one
	// as a finding.
	attempts := r.candidateAttempts(parsed)

	tmpFile, err := os.CreateTemp("", "gowitness-rtsp-*.jpg")
	if err != nil {
		return nil, fmt.Errorf("rtsp tempfile: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	var lastReason string
	var imgBytes []byte
	var winningLabel string
	for i, c := range attempts {
		// pre-truncate output between attempts so a previous attempt's
		// stale frame can't be picked up if a later attempt fails.
		_ = os.WriteFile(tmpPath, nil, 0o600)

		body, reason := r.attempt(c.dialURL, tmpPath, timeout)
		if len(body) > 0 {
			imgBytes = body
			winningLabel = c.label
			r.log.Debug("rtsp frame captured",
				"target", saveURL,
				"attempt", i+1, "of", len(attempts),
				"creds", c.label,
			)
			break
		}
		lastReason = reason
	}

	if len(imgBytes) == 0 {
		result.Failed = true
		if lastReason == "" {
			lastReason = "no frame captured"
		}
		result.FailedReason = lastReason
		// Sentinel: keep the row in writers so the operator sees the
		// failure (and reason) without having to scroll through stderr.
		result.ResponseCode = 1
		r.log.Warn("rtsp scan failed",
			"target", saveURL,
			"reason", lastReason,
			"attempts", len(attempts),
		)
		return result, nil
	}

	decoded, _, err := image.Decode(bytes.NewReader(imgBytes))
	if err != nil {
		result.Failed = true
		result.FailedReason = fmt.Sprintf("decode frame: %s", err)
		return result, nil
	}

	encoded, err := encodeImage(decoded, r.options)
	if err != nil {
		return nil, err
	}

	if r.options.Scan.ScreenshotToWriter {
		result.Screenshot = base64.StdEncoding.EncodeToString(encoded)
	}

	if err := finalizeScreenshot(result, saveURL, encoded, decoded, r.options); err != nil {
		return nil, err
	}

	bounds := decoded.Bounds()
	result.Title = fmt.Sprintf("RTSP %s", parsed.Hostname())
	result.FinalURL = saveURL
	result.ResponseCode = 200
	result.ResponseReason = "OK"
	result.Protocol = fmt.Sprintf("rtsp/%dx%d", bounds.Dx(), bounds.Dy())
	// Only record the winning ladder credential as a finding. The empty
	// label (for URL-supplied or CLI-supplied creds) means "operator
	// already knew" and should not be surfaced as a discovery.
	result.DiscoveredCreds = winningLabel

	return result, nil
}

// credAttempt is one rung of the RTSP credential ladder.
type credAttempt struct {
	// dialURL is what we hand to ffmpeg.
	dialURL string
	// label is the human-readable credentials description, persisted on
	// success only when the ladder discovered them. Empty string means
	// the operator already knew (URL- or CLI-supplied) and the success
	// is not a finding.
	label string
}

// candidateAttempts returns the ordered list of attempts ffmpeg will try.
// Order:
//
//  1. URL-embedded creds, if present (one attempt; not a finding)
//  2. CLI --rtsp-username/--rtsp-password, if set (one attempt; not a
//     finding)
//  3. Anonymous + each --rtsp-default-creds entry in turn. Successful
//     attempts here ARE persisted as DiscoveredCreds findings.
//
// Empty entries in DefaultCreds are silently skipped.
func (r *RTSP) candidateAttempts(parsed *url.URL) []credAttempt {
	if parsed.User != nil {
		return []credAttempt{{dialURL: parsed.String()}}
	}
	if r.options.RTSP.Username != "" {
		clone := *parsed
		clone.User = url.UserPassword(r.options.RTSP.Username, r.options.RTSP.Password)
		return []credAttempt{{dialURL: clone.String()}}
	}

	out := []credAttempt{
		{dialURL: parsed.String(), label: "anonymous"},
	}
	seen := map[string]struct{}{out[0].dialURL: {}}
	for _, pair := range r.options.RTSP.DefaultCreds {
		if pair == "" {
			continue
		}
		user, pass, ok := splitUserPass(pair)
		if !ok {
			r.log.Debug("ignoring malformed rtsp-default-creds entry", "value", pair)
			continue
		}
		clone := *parsed
		clone.User = url.UserPassword(user, pass)
		u := clone.String()
		if _, dup := seen[u]; dup {
			continue
		}
		seen[u] = struct{}{}
		out = append(out, credAttempt{dialURL: u, label: pair})
	}
	return out
}

// attempt invokes ffmpeg once for one dial URL. Returns the captured
// frame bytes (or nil) and a short failure reason (or "" on success).
//
// We use -rw_timeout (microseconds) for I/O timeouts because the older
// RTSP-specific -stimeout was deprecated in ffmpeg 5 and removed in
// ffmpeg 6+. The Go context timeout is the hard upper bound and kills
// the process via SIGKILL if ffmpeg ignores its own timeouts.
func (r *RTSP) attempt(dialURL, tmpPath string, timeout time.Duration) ([]byte, string) {
	transport := r.options.RTSP.Transport
	if transport == "" {
		transport = "tcp"
	}

	rwTimeout := strconv.FormatInt(timeout.Microseconds(), 10)

	args := []string{
		"-hide_banner",
		"-nostdin",
		"-loglevel", "error",
		"-rw_timeout", rwTimeout,
		"-rtsp_transport", transport,
		"-i", dialURL,
		"-frames:v", "1",
		"-update", "1",
		"-y",
		tmpPath,
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout+5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, r.ffmpeg, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	stderrText := strings.TrimSpace(stderr.String())
	if err != nil {
		// Surface the FULL ffmpeg stderr at debug level so an operator
		// running with -D can see what really happened. The caller
		// records the truncated first line as result.FailedReason.
		if stderrText != "" {
			r.log.Debug("ffmpeg stderr", "url", redactURL(dialURL), "stderr", stderrText)
		}
		reason := truncateLine(stderrText)
		if reason == "" {
			reason = err.Error()
		}
		return nil, fmt.Sprintf("ffmpeg: %s", reason)
	}

	body, ferr := os.ReadFile(tmpPath)
	if ferr != nil || len(body) == 0 {
		if stderrText != "" {
			r.log.Debug("ffmpeg produced no frame",
				"url", redactURL(dialURL), "stderr", stderrText)
		}
		return nil, "no frame captured"
	}
	return body, ""
}

// redactURL strips userinfo from a URL string so logs don't leak the
// password being tried.
func redactURL(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return s
	}
	u.User = nil
	return u.String()
}

// splitUserPass parses a "user:pass" pair, supporting an empty password
// ("admin:" → user=admin, pass=""). The first colon separates the two
// fields; remaining colons stay in the password.
func splitUserPass(pair string) (string, string, bool) {
	for i := 0; i < len(pair); i++ {
		if pair[i] == ':' {
			return pair[:i], pair[i+1:], true
		}
	}
	return "", "", false
}

func (r *RTSP) Close() {}

// sanitizeRTSPURL strips userinfo (credentials) from an rtsp:// URL so
// creds never end up in the database or exports.
func sanitizeRTSPURL(u *url.URL) string {
	clone := *u
	clone.User = nil
	return clone.String()
}

// truncateLine extracts the first non-empty line of ffmpeg's stderr
// output and trims it to a reasonable length for the FailedReason
// column. Multi-line ffmpeg errors are noisy; the first line is almost
// always the meaningful one.
func truncateLine(s string) string {
	const max = 200
	for _, line := range bytes.Split([]byte(s), []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if len(line) > max {
			return string(line[:max]) + "..."
		}
		return string(line)
	}
	return ""
}

// keep stricter type-safety: confirm RTSP implements Driver.
var _ runner.Driver = (*RTSP)(nil)
