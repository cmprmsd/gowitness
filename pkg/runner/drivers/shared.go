package driver

import (
	"bytes"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/sensepost/gowitness/internal/islazy"
	"github.com/sensepost/gowitness/pkg/imagehash"
	"github.com/sensepost/gowitness/pkg/models"
	"github.com/sensepost/gowitness/pkg/runner"
)

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
