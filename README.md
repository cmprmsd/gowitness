<h1 align="center">
  <br>
    gowitness
  <br>
  <br>
</h1>

<h4 align="center">A golang, web screenshot utility using Chrome Headless.</h4>
<p align="center">
  <a href="https://twitter.com/leonjza"><img src="https://img.shields.io/badge/twitter-%40leonjza-blue.svg" alt="@leonjza" height="18"></a>
  <a href="https://goreportcard.com/report/github.com/cmprmsd/gowitness"><img src="https://goreportcard.com/badge/github.com/cmprmsd/gowitness" alt="Go Report Card" height="18"></a>
  <a href="https://github.com/cmprmsd/gowitness/actions/workflows/docker.yml"><img alt="Docker build & Push" src="https://github.com/cmprmsd/gowitness/actions/workflows/docker.yml/badge.svg"></a>
</p>
<br>

## fork additions

This is a fork of [`sensepost/gowitness`](https://github.com/sensepost/gowitness) that extends the screenshot pipeline beyond HTTP:

- **VNC driver** (`vnc://host[:5900]`) — captures the framebuffer via RFB. Implements the **CVE-2006-2369** authentication bypass against vulnerable old RealVNC servers by forcing security type 1 (None).
- **RDP driver** (`rdp://host[:3389]`) — negotiates Standard RDP or SSL/TLS (no NLA) and captures the login-screen bitmap. Windows hosts with NLA disabled work out of the box; NLA-required servers surface a clear "server requires NLA (HYBRID)" reason.
- **RTSP driver** (`rtsp://host[:554]`) — grabs a single video frame via ffmpeg. Walks a **default-credential ladder** (`admin:admin`, `admin:`, `admin:12345`, `admin:888888`, `root:root`, `admin:password`) and records the winning creds as a **discovered-credentials finding** — visible in the gallery as a yellow key badge on the card and as an advisory banner on the detail page.
- **Favicon-hash tagger** — every HTTP result is classified into operator-friendly tags (`printer` / `firewall` / `hypervisor` / `Canon Remote UI` / `pfSense` / etc.) using a Shodan-compatible MMH3 favicon hash seeded from [`edoardottt/favirecon`](https://github.com/edoardottt/favirecon) (~1400 rules) plus hand-curated title-based rules. Override the ruleset with `--tags-file rules.yaml`.
- **Reader routing** — the nmap / nessus / cidr readers detect VNC / RDP / RTSP services by service name and well-known port and emit the matching URL scheme instead of always trying `http(s)://`. A single `gowitness scan nmap -f scan.xml --open-only --write-db` now produces web *and* VNC *and* RDP *and* camera screenshots in one pass.
- **Gallery filters** — multi-select filters for **Protocol** and **Tag** (grouped by Category / Vendor / Product) with popovers that stay open across multiple selections. Click the hover-only external-link button on a card to open the target URL in a new tab without navigating to the detail page.

Runtime deps for the extra drivers: `ffmpeg` is required for RTSP (not for VNC/RDP). Missing ffmpeg logs a startup warning; only `rtsp://` targets fail.

<br>

## introduction

`gowitness` is a website screenshot utility written in Golang, that uses Chrome Headless to generate screenshots of web interfaces using the command line, with a handy report viewer to process results. Both Linux and macOS is supported, with Windows support mostly working.

## features

The main goal of `gowitness` is to take website screenshots (**and do that well!**), while optionally saving any information it gathered along the way. That said, a short list of features include:

- Take website screenshots, obviously..., but fast and accurate!
- Scan a list of URLs, CIDRs, Nmap Results, Nessus Results and more.
- Ability to grab and save data (i.e., a request log, console logs, headers, cookies, etc.)
- Write data to many formats (sqlite database, jsonlines, csv, etc.)
- An epic web-based results viewer (if you saved data to SQLite) including a fully featured API!
- And many, many more!

## quick start

There are a few ways to get gowitness, the simplest (assuming your `$GOBIN` path is in your shell `$PATH`) will be to use `go install`:

```text
go install github.com/cmprmsd/gowitness@latest
```

Otherwise, grab a platform specific release binary or compile from source. Then, scan your first target writing the results to a SQLite database and the screenshot to `./screenshots` with:

```text
gowitness scan single --url "https://sensepost.com" --write-db
```

There are many, *many* flags and scan types in `gowitness`. Just add `-h` anywhere and read all about it!

## documentation

For advanced installation information and other documentation, please refer to the wiki [here](https://github.com/cmprmsd/gowitness/wiki).

## screenshots

![gallery](images/gowitness-gallery.png)

![detail](images/gowitness-detail.png)

![terminal](images/gowitness-terminal.png)

## credits

`gowitness` would not have been possible without some of [these amazing projects](./go.mod): [chi](https://github.com/go-chi/chi), [chromedp](https://github.com/chromedp/chromedp), [go-rod](https://github.com/go-rod/rod), [cobra](https://github.com/spf13/cobra), [gorm](https://github.com/go-gorm/gorm), [glamour](https://github.com/charmbracelet/glamour), [go-nmap](https://github.com/lair-framework/go-nmap), [wappalyzergo](https://github.com/projectdiscovery/wappalyzergo), [goimagehash](https://github.com/corona10/goimagehash).

## license

`gowitness` is licensed under a [GNU General Public v3 License](https://www.gnu.org/licenses/gpl-3.0.en.html). Permissions beyond the scope of this license may be available at <http://sensepost.com/contact/>.
