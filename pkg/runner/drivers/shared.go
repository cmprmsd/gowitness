package driver

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/cmprmsd/gowitness/internal/islazy"
	"github.com/cmprmsd/gowitness/internal/tagger"
	"github.com/cmprmsd/gowitness/pkg/imagehash"
	"github.com/cmprmsd/gowitness/pkg/models"
	"github.com/cmprmsd/gowitness/pkg/runner"
)

// faviconFetchScript is the JavaScript snippet evaluated in the page
// context to fetch /favicon.ico (or the document's <link rel="icon">) and
// return its body as a base64-encoded string. Empty string means "no
// favicon retrievable" - the caller should fall back to title/header
// matchers.
//
// Running inside the page reuses Chrome's existing cookies, headers and
// proxy state, so auth-gated favicons work without a parallel HTTP
// fetcher.
const faviconFetchScript = `
(async () => {
  try {
    const linkEl = document.querySelector('link[rel~="icon"], link[rel~="shortcut"]');
    const candidates = [];
    if (linkEl && linkEl.href) candidates.push(linkEl.href);
    candidates.push('/favicon.ico');
    for (const u of candidates) {
      try {
        const r = await fetch(u, { credentials: 'include' });
        if (!r.ok) continue;
        const buf = await r.arrayBuffer();
        if (!buf || buf.byteLength === 0) continue;
        const bytes = new Uint8Array(buf);
        let bin = '';
        for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        return btoa(bin);
      } catch (_) {}
    }
  } catch (_) {}
  return '';
})();
`

// applyTags decodes a base64 favicon body (possibly empty), computes its
// Shodan hash, runs the tagger, and appends matched tags to the result.
// Safe to call with an empty/invalid favicon body or when the tagger is
// nil - it just falls back to title/header matching, or no-ops.
func applyTags(result *models.Result, faviconB64 string, run *runner.Runner) {
	if run == nil || run.Tagger == nil {
		return
	}

	in := tagger.MatchInput{
		Title:   result.Title,
		Headers: result.HeaderMap(),
		Body:    result.HTML,
	}
	for _, t := range result.Technologies {
		in.Technologies = append(in.Technologies, t.Value)
	}

	if faviconB64 != "" {
		if raw, err := base64.StdEncoding.DecodeString(faviconB64); err == nil && len(raw) > 0 {
			if h, err := tagger.ShodanHash(raw); err == nil {
				in.FaviconHash = h
				in.HasFavicon = true
			}
		}
	}

	for _, tag := range run.Tagger.Match(in) {
		result.Tags = append(result.Tags, models.Tag{Value: tag})
	}
}

// parseScheme returns the lowercased scheme (http, https, vnc, rdp, ...) of a
// target URL. Returns an empty string when parsing fails.
func parseScheme(target string) string {
	parsed, err := url.Parse(target)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Scheme)
}

// encodeImage encodes a Go image.Image to JPEG or PNG bytes based on the
// configured screenshot format.
func encodeImage(img image.Image, opts runner.Options) ([]byte, error) {
	var buf bytes.Buffer

	switch opts.Scan.ScreenshotFormat {
	case "png":
		if err := png.Encode(&buf, img); err != nil {
			return nil, fmt.Errorf("png encode: %w", err)
		}
	case "jpeg":
		quality := opts.Scan.ScreenshotJpegQuality
		if quality <= 0 || quality > 100 {
			quality = 60
		}
		if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: quality}); err != nil {
			return nil, fmt.Errorf("jpeg encode: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported screenshot format: %s", opts.Scan.ScreenshotFormat)
	}

	return buf.Bytes(), nil
}

// finalizeScreenshot writes encoded screenshot bytes to disk (when enabled)
// and computes a perception hash. It mutates the result with Filename and
// PerceptionHash.
func finalizeScreenshot(result *models.Result, target string, encoded []byte, decoded image.Image, opts runner.Options) error {
	if !opts.Scan.ScreenshotSkipSave {
		filename := islazy.SafeFileName(target) + "." + opts.Scan.ScreenshotFormat
		filename = islazy.LeftTrucate(filename, 200)
		result.Filename = filename

		if err := os.WriteFile(
			filepath.Join(opts.Scan.ScreenshotPath, result.Filename),
			encoded, os.FileMode(0664),
		); err != nil {
			return fmt.Errorf("could not write screenshot to disk: %w", err)
		}
	}

	hash, err := imagehash.PerceptionHash(decoded)
	if err != nil {
		return fmt.Errorf("could not calculate perception hash: %w", err)
	}
	result.PerceptionHash = hash
	return nil
}
