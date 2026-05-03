package cmd

import (
	"errors"
	"log/slog"

	"github.com/sensepost/gowitness/internal/ascii"
	"github.com/sensepost/gowitness/pkg/log"
	"github.com/sensepost/gowitness/pkg/runner"
	driver "github.com/sensepost/gowitness/pkg/runner/drivers"
	"github.com/sensepost/gowitness/pkg/writers"
	"github.com/spf13/cobra"
)

var scanWriters = []writers.Writer{}
var scanDrivers = map[string]runner.Driver{}
var scanRunner *runner.Runner

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Perform various scans",
	Long: ascii.LogoHelp(ascii.Markdown(`
# scan

Perform various scans using sources such as a file, Nmap XMLs, Nessus exports,
or by scanning network CIDR ranges.

By default, gowitness will only take screenshots. However, that is only half
the fun! You can add multiple _writers_ that will collect information such as
response codes, content, and more. You can specify multiple writers using the
_--writer-*_ flags (see --help).

**Note**: By default, no metadata is saved except for screenshots that are
stored in the configured --screenshot-path. For later parsing (i.e., using the
gowitness reporting feature), you need to specify where to write results (db,
csv, jsonl) using the _--write-*_ set of flags. See _--help_ for available
flags.`)),
	Example: ascii.Markdown(`
- gowitness scan nessus -f ./scan-results.nessus --port 80 --write-jsonl
- gowitness scan file -f ~/targets.txt --no-http --save-content --write-db
- gowitness scan cidr -t 20 --log-scan-errors -c 10.20.20.0/28
- cat targets.txt | gowitness scan file - --write-db --write-jsonl`),
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		var err error

		// Annoying quirk, but because I'm overriding PersistentPreRun
		// here which overrides the parent it seems.
		// So we need to explicitly call the parent's one now.
		if err = rootCmd.PersistentPreRunE(cmd, args); err != nil {
			return err
		}

		// An slog-capable logger to use with drivers and runners
		logger := slog.New(log.Logger)

		// Build the per-scheme driver map. The HTTP driver is registered for
		// both http and https schemes. VNC and RDP drivers are dialed lazily
		// only when their scheme is enabled in --uri-filter.
		schemeFilter := map[string]bool{}
		for _, s := range opts.Scan.UriFilter {
			schemeFilter[s] = true
		}

		// HTTP driver (chromedp or gorod) registered when http or https is
		// enabled. Skip Chrome instantiation entirely if neither is enabled.
		if schemeFilter["http"] || schemeFilter["https"] {
			var httpDriver runner.Driver
			switch opts.Scan.Driver {
			case "gorod":
				httpDriver, err = driver.NewGorod(logger, *opts)
				if err != nil {
					return err
				}
			case "chromedp":
				httpDriver, err = driver.NewChromedp(logger, *opts)
				if err != nil {
					return err
				}
			default:
				return errors.New("invalid scan driver chosen")
			}
			if schemeFilter["http"] {
				scanDrivers["http"] = httpDriver
			}
			if schemeFilter["https"] {
				scanDrivers["https"] = httpDriver
			}
			log.Debug("http driver started", "driver", opts.Scan.Driver)
		}

		// VNC driver
		if schemeFilter["vnc"] {
			vncDriver, err := driver.NewVNC(logger, *opts)
			if err != nil {
				return err
			}
			scanDrivers["vnc"] = vncDriver
			log.Debug("vnc driver started")
		}

		// RDP driver
		if schemeFilter["rdp"] {
			rdpDriver, err := driver.NewRDP(logger, *opts)
			if err != nil {
				return err
			}
			scanDrivers["rdp"] = rdpDriver
			log.Debug("rdp driver started")
		}

		// RTSP driver
		if schemeFilter["rtsp"] {
			rtspDriver, err := driver.NewRTSP(logger, *opts)
			if err != nil {
				return err
			}
			scanDrivers["rtsp"] = rtspDriver
			log.Debug("rtsp driver started")
		}

		if len(scanDrivers) == 0 {
			return errors.New("no scan drivers enabled (check --uri-filter)")
		}

		// Configure writers that subcommand scanners will pass to
		// a runner instance.
		if opts.Writer.Jsonl {
			w, err := writers.NewJsonWriter(opts.Writer.JsonlFile)
			if err != nil {
				return err
			}
			scanWriters = append(scanWriters, w)
		}

		if opts.Writer.Db {
			w, err := writers.NewDbWriter(opts.Writer.DbURI, opts.Writer.DbDebug)
			if err != nil {
				return err
			}
			scanWriters = append(scanWriters, w)
		}

		if opts.Writer.Csv {
			w, err := writers.NewCsvWriter(opts.Writer.CsvFile)
			if err != nil {
				return err
			}
			scanWriters = append(scanWriters, w)
		}

		if opts.Writer.Stdout {
			w, err := writers.NewStdoutWriter()
			if err != nil {
				return err
			}
			scanWriters = append(scanWriters, w)
		}

		if opts.Writer.None {
			w, err := writers.NewNoneWriter()
			if err != nil {
				return err
			}
			scanWriters = append(scanWriters, w)
		}

		if len(scanWriters) == 0 {
			log.Warn("no writers have been configured. to persist probe results, add writers using --write-* flags")
		}

		// Get the runner up. Basically, all of the subcommands will use this.
		scanRunner, err = runner.NewRunner(logger, scanDrivers, *opts, scanWriters)
		if err != nil {
			return err
		}

		return nil
		// TODO: maybe add https://github.com/projectdiscovery/networkpolicy support?
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	// Logging control for subcommands
	scanCmd.PersistentFlags().BoolVar(&opts.Logging.LogScanErrors, "log-scan-errors", false, "Log scan errors (timeouts, DNS errors, etc.) to stderr (warning: can be verbose!)")

	// "Threads" & other
	scanCmd.PersistentFlags().StringVarP(&opts.Scan.Driver, "driver", "", "chromedp", "The scan driver to use. Can be one of [gorod, chromedp]")
	scanCmd.PersistentFlags().IntVarP(&opts.Scan.Threads, "threads", "t", 6, "Number of concurrent threads (goroutines) to use")
	scanCmd.PersistentFlags().IntVarP(&opts.Scan.Timeout, "timeout", "T", 60, "Number of seconds before considering a page timed out")
	scanCmd.PersistentFlags().IntVar(&opts.Scan.Delay, "delay", 3, "Number of seconds delay between navigation and screenshotting")
	scanCmd.PersistentFlags().StringSliceVar(&opts.Scan.UriFilter, "uri-filter", []string{"http", "https", "vnc", "rdp", "rtsp"}, "Valid URIs to pass to the scanning process. Determines which drivers are activated.")
	scanCmd.PersistentFlags().StringVarP(&opts.Scan.ScreenshotPath, "screenshot-path", "s", "./screenshots", "Path to store screenshots")
	scanCmd.PersistentFlags().StringVar(&opts.Scan.ScreenshotFormat, "screenshot-format", "jpeg", "Format to save screenshots as. Valid formats are: jpeg, png")
	scanCmd.PersistentFlags().IntVar(&opts.Scan.ScreenshotJpegQuality, "screenshot-jpeg-quality", 60, "The quality of JPEG screenshots (1-100)")
	scanCmd.PersistentFlags().BoolVar(&opts.Scan.ScreenshotFullPage, "screenshot-fullpage", false, "Do full-page screenshots, instead of just the viewport")
	scanCmd.PersistentFlags().BoolVar(&opts.Scan.ScreenshotSkipSave, "screenshot-skip-save", false, "Do not save screenshots to the screenshot-path (useful together with --write-screenshots)")
	scanCmd.PersistentFlags().StringVar(&opts.Scan.JavaScript, "javascript", "", "A JavaScript function to evaluate on every page, before a screenshot. Note: It must be a JavaScript function! e.g., () => console.log('gowitness');")
	scanCmd.PersistentFlags().StringVar(&opts.Scan.JavaScriptFile, "javascript-file", "", "A file containing a JavaScript function to evaluate on every page, before a screenshot. See --javascript")
	scanCmd.PersistentFlags().BoolVar(&opts.Scan.SaveContent, "save-content", false, "Save content from network requests to the configured writers. WARNING: This flag has the potential to make your storage explode in size")
	scanCmd.PersistentFlags().BoolVar(&opts.Scan.SkipHTML, "skip-html", false, "Don't include the first request's HTML response when writing results")
	scanCmd.PersistentFlags().BoolVar(&opts.Scan.SkipNetworkLogs, "skip-network-logs", false, "Don't include per-request network logs when writing results (also disables save-content)")
	scanCmd.PersistentFlags().BoolVar(&opts.Scan.ScreenshotToWriter, "write-screenshots", false, "Store screenshots with writers in addition to filesystem storage")
	scanCmd.PersistentFlags().IntSliceVar(&opts.Scan.HttpCodeFilter, "http-code-filter", []int{}, "Http response codes to screenshot. This is a filter (by default all codes are screenshotted)")
	scanCmd.PersistentFlags().StringVar(&opts.Scan.TagsFile, "tags-file", "", "Path to a YAML rules file overriding the embedded tagger ruleset")
	scanCmd.PersistentFlags().BoolVar(&opts.Scan.DisableTags, "no-tags", false, "Disable favicon-hash + YAML tagging")

	// Chrome options
	scanCmd.PersistentFlags().StringVar(&opts.Chrome.Path, "chrome-path", "", "The path to a Google Chrome binary to use (downloads a platform-appropriate binary by default)")
	scanCmd.PersistentFlags().StringVar(&opts.Chrome.Proxy, "chrome-proxy", "", "An HTTP/SOCKS5 proxy server to use. Specify the proxy using this format: proto://address:port")
	scanCmd.PersistentFlags().StringVar(&opts.Chrome.WSS, "chrome-wss-url", "", "A websocket URL to connect to a remote, already running Chrome DevTools instance (i.e., Chrome started with --remote-debugging-port)")
	scanCmd.PersistentFlags().StringVar(&opts.Chrome.UserAgent, "chrome-user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36", "The user-agent string to use")
	scanCmd.PersistentFlags().IntVar(&opts.Chrome.WindowX, "chrome-window-x", 1280, "The Chrome browser window width, in pixels")
	scanCmd.PersistentFlags().IntVar(&opts.Chrome.WindowY, "chrome-window-y", 720, "The Chrome browser window height, in pixels")
	scanCmd.PersistentFlags().StringArrayVar(&opts.Chrome.Headers, "chrome-header", []string{}, "Extra headers to add to requests. Supports multiple --chrome-header flags")

	// VNC options
	scanCmd.PersistentFlags().IntVar(&opts.VNC.Port, "vnc-port", 5900, "Default port for vnc:// targets that omit a port")
	scanCmd.PersistentFlags().BoolVar(&opts.VNC.ForceNoAuth, "vnc-force-none", true, "Force RFB security type 1 (None) even if not advertised by the server (CVE-2006-2369 style auth bypass)")
	scanCmd.PersistentFlags().IntVar(&opts.VNC.SettleTime, "vnc-settle-time", 2, "Seconds to wait for additional framebuffer rectangles after the initial update before screenshotting")

	// RDP options
	scanCmd.PersistentFlags().IntVar(&opts.RDP.Port, "rdp-port", 3389, "Default port for rdp:// targets that omit a port")
	scanCmd.PersistentFlags().IntVar(&opts.RDP.SettleTime, "rdp-settle-time", 5, "Seconds to wait for the login screen to render before screenshotting")
	scanCmd.PersistentFlags().StringVar(&opts.RDP.Username, "rdp-username", "", "Default RDP username (Standard RDP security only - no NLA)")
	scanCmd.PersistentFlags().StringVar(&opts.RDP.Password, "rdp-password", "", "Default RDP password")
	scanCmd.PersistentFlags().StringVar(&opts.RDP.Domain, "rdp-domain", "", "Default RDP domain")

	// RTSP options
	scanCmd.PersistentFlags().IntVar(&opts.RTSP.Port, "rtsp-port", 554, "Default port for rtsp:// targets that omit a port")
	scanCmd.PersistentFlags().StringVar(&opts.RTSP.Transport, "rtsp-transport", "tcp", "RTSP transport [tcp|udp]")
	scanCmd.PersistentFlags().StringVar(&opts.RTSP.Username, "rtsp-username", "", "Default RTSP username when not embedded in the URL")
	scanCmd.PersistentFlags().StringVar(&opts.RTSP.Password, "rtsp-password", "", "Default RTSP password")
	scanCmd.PersistentFlags().StringSliceVar(&opts.RTSP.DefaultCreds, "rtsp-default-creds",
		[]string{"admin:admin", "admin:", "admin:12345", "admin:888888", "root:root", "admin:password"},
		"Comma-separated list of user:pass pairs to try after anonymous; pass an empty value to disable")

	// Write options for scan subcommands
	scanCmd.PersistentFlags().BoolVar(&opts.Writer.Db, "write-db", false, "Write results to a SQLite database")
	scanCmd.PersistentFlags().StringVar(&opts.Writer.DbURI, "write-db-uri", "sqlite://gowitness.sqlite3", "The database URI to use. Supports SQLite, MySQL, and PostgreSQL. Examples: sqlite://gowitness.sqlite3, mysql://user:pass@localhost:3306/gowitness, postgres://user:pass@localhost:5432/gowitness")
	scanCmd.PersistentFlags().BoolVar(&opts.Writer.DbDebug, "write-db-enable-debug", false, "Enable database query debug logging (warning: vebose!)")
	scanCmd.PersistentFlags().BoolVar(&opts.Writer.Csv, "write-csv", false, "Write results as CSV (has limited columns)")
	scanCmd.PersistentFlags().StringVar(&opts.Writer.CsvFile, "write-csv-file", "gowitness.csv", "The file to write CSV rows to")
	scanCmd.PersistentFlags().BoolVar(&opts.Writer.Jsonl, "write-jsonl", false, "Write results as JSON lines")
	scanCmd.PersistentFlags().StringVar(&opts.Writer.JsonlFile, "write-jsonl-file", "gowitness.jsonl", "The file to write JSON lines to")
	scanCmd.PersistentFlags().BoolVar(&opts.Writer.Stdout, "write-stdout", false, "Write successful results to stdout (usefull in a shell pipeline)")
	scanCmd.PersistentFlags().BoolVar(&opts.Writer.None, "write-none", false, "Use an empty writer to silence warnings")
}
