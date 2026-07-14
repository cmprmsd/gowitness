# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository identity

This is the `cmprmsd/gowitness` fork of `sensepost/gowitness`. The module path was intentionally renamed to `github.com/cmprmsd/gowitness` because the fork has diverged (see fork-specific features below). Do NOT rewrite imports back to `sensepost`; upstream merges will conflict on every file and that's expected.

## Fork-specific features

Beyond upstream's HTTP/HTTPS screenshot pipeline, this fork adds:

- **Non-HTTP drivers**: VNC (with CVE-2006-2369 auth-bypass), RDP (Standard + SSL/TLS, no NLA), RTSP (via ffmpeg subprocess with credential-ladder default probing). Each URL scheme dispatches to its driver via `Runner.Drivers map[string]Driver`.
- **Favicon-hash tagger** (`internal/tagger/`): Shodan-compatible MMH3 favicon hashing + YAML rules embedded at build time (`rules.yaml`, seeded from `edoardottt/favirecon`). `--tags-file` overrides. Each match emits up to 3 tags (name / category / vendor).
- **Discovered credentials**: default-credential probes for RTSP surface working creds in `models.Result.DiscoveredCreds` and light up a yellow badge in the gallery.
- **Reader scheme routing**: nmap/nessus/cidr readers detect VNC/RDP/RTSP services (by service name for nmap/nessus, by well-known port for cidr) and emit `vnc://`, `rdp://`, `rtsp://` URLs instead of always `http(s)://`.

## Build / test / develop

```bash
make            # clean + test + frontend + api-doc + build (linux/amd64 by default)
make test       # go test ./...
make frontend   # cd web/ui && npm i && npm run build (regenerates web/ui/dist/)
make api-doc    # swag i --exclude ./web/ui --output web/docs (regenerates web/docs/swagger.json)
make linux/amd64  # single-platform build with version stamping

go test ./internal/tagger/...      # single package
go test ./... -run TestFavicon     # single test
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" .
```

Release builds are `CGO_ENABLED=0` (static binary). Anything that requires cgo transitively will silently break these builds — see `third_party/grdp/` below.

## Architecture

### Driver pipeline

`cmd/scan.go` builds `scanDrivers map[string]runner.Driver` (registered under scheme keys `http`/`https`/`vnc`/`rdp`/`rtsp`) and hands it to `runner.NewRunner`. `Runner.Run()` (`pkg/runner/runner.go`) spawns worker goroutines that pull from `Runner.Targets`, parse each URL's scheme, and dispatch to the matching driver. **Adding a new protocol driver = implement the `Driver` interface (`Witness(target, run) (*models.Result, error)` + `Close()`), register it under its scheme in `cmd/scan.go`, and add scheme detection to `pkg/readers/scheme.go`.**

The runner drops results where `ResponseCode == 0`. VNC/RDP/RTSP drivers set `ResponseCode = 200` only on success; failure paths log a `WARN` and let the runner drop the row. This is intentional — completely-failed non-HTTP probes have no gallery content.

### Screenshot lifecycle inside a driver

1. Capture bytes (chromedp/rod for HTTP; RFB framebuffer for VNC; grdp bitmap rects for RDP; ffmpeg frame grab for RTSP).
2. Decode to `image.Image`, then `pkg/runner/drivers/shared.go` handles: `encodeImage` (JPEG/PNG), perception hash, disk write, base64 (when `--write-screenshots`).
3. Wappalyzer fingerprints tech, then `applyTags` runs the favicon-hash/YAML tagger. Tagger only runs for HTTP drivers (favicon is fetched by evaluating JS in the page context so cookies/proxy state are preserved).

### Web UI + API

Go backend serves at `web/server.go` (chi router). React frontend under `web/ui/src/` builds to `web/ui/dist/` and is embedded via `//go:embed ui/dist/*` in `web/spa.go`. **Any UI change requires `npm run build` AND `go build` to re-embed dist.** The `dist/*` files are committed to the repo (repo precedent: see `git log web/ui/dist/`).

API endpoints live in `web/api/`. Response structs are separate from GORM models — when adding a field to `models.Result` you almost always need to also add it to `galleryContent`, `listResponse`, `searchResult`, and the corresponding TS interfaces in `web/ui/src/lib/api/types.ts`.

### Tagger

`internal/tagger/tagger.go` loads YAML rules embedded via `//go:embed rules.yaml`. `Match()` returns `[]TaggedValue{Value, Type}` where Type is `"name"`, `"category"`, or `"vendor"`. Favicon-hash matchers run first; only if none hit does the matcher fall back to title/header/body/tech matchers. Test with `go test ./internal/tagger/`; the ShodanHash algorithm is cross-checked against Python's mmh3 in a known-vector test.

### Vendored/patched deps

- **`internal/vnc/`**: vendored `mitchellh/go-vnc` (MIT), patched to support RFB 3.7 and a `ClientConfig.ForceNoAuth` flag for the CVE-2006-2369 bypass.
- **`third_party/grdp/`**: patched `tomatome/grdp` used via `go.mod replace github.com/tomatome/grdp => ./third_party/grdp`. Upstream's `plugin/channel.go` does `import "C"`, so under `CGO_ENABLED=0` the entire package becomes empty and `t125/gcc` can't resolve its channel-name string constants. The patch splits the file with build tags: `channel.go` gets `//go:build cgo`, and `channel_nocgo.go` provides the constants for non-cgo builds. **Don't remove the replace directive** — release builds break without it.

## Commit conventions

Commits use lowercase tag prefixes: `(feat)`, `(fix)`, `(feat/ui)`, `(fix/ui)`, `(refactor)`, `(chore)`, `(chore/ui)`. Every commit body includes a `https://claude.ai/code/session_...` trailer.

## Runtime dependencies

- **Chrome** — auto-downloaded on first HTTP scan by chromedp/rod; skip with `--chrome-path`.
- **ffmpeg** — required for RTSP scans. Missing ffmpeg is a startup `WARN`, not a fatal error; rtsp:// targets just fail with a clear reason. Don't reintroduce ffmpeg-specific timeout flags (`-stimeout`, `-rw_timeout`, `-timeout`) — their names and units vary wildly across ffmpeg 4/5/6/7. The Go context's `SIGKILL` handles hard timeouts.
