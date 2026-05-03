// Package tagger classifies HTTP scan results into operator-friendly tags
// (printer, firewall, hypervisor, ipmi, ...) using a small rules engine.
//
// Each rule has at least one matcher. Favicon-hash matchers are the
// preferred signal and run first — only if no rule matches by favicon
// hash does the tagger fall back to title / header / body / wappalyzer
// matchers. A matched rule contributes up to three tags to the result:
// its name (specific product), its category, and its vendor.
//
// The default ruleset is embedded into the binary at build time from
// rules.yaml. Callers can supply an override path with
// LoadFromFile.
package tagger

import (
	_ "embed"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed rules.yaml
var defaultRules []byte

// Rule is a single classification rule loaded from YAML.
//
// FaviconHash accepts either a single int or a list. The custom
// UnmarshalYAML below normalises both into FaviconHashes.
type Rule struct {
	Name           string            `yaml:"name"`
	Category       string            `yaml:"category,omitempty"`
	Vendor         string            `yaml:"vendor,omitempty"`
	FaviconHash    yaml.Node         `yaml:"favicon_hash,omitempty"`
	TitleRegex     string            `yaml:"title_regex,omitempty"`
	TitleContains  []string          `yaml:"title_contains,omitempty"`
	HeaderContains map[string]string `yaml:"header_contains,omitempty"`
	BodyContains   []string          `yaml:"body_contains,omitempty"`
	TechContains   []string          `yaml:"tech_contains,omitempty"`

	// derived at load time so we don't recompile per match
	faviconHashes  []int32
	titleRegexComp *regexp.Regexp
}

type rulesFile struct {
	Rules []*Rule `yaml:"rules"`
}

// MatchInput is the data the tagger needs to evaluate every matcher
// against a single result. FaviconHash should be the Shodan-style
// 32-bit signed MurmurHash3 of the page's favicon, or 0 + HasFavicon
// = false when no favicon is available.
type MatchInput struct {
	FaviconHash  int32
	HasFavicon   bool
	Title        string
	Headers      map[string][]string
	Body         string
	Technologies []string
}

// Tagger holds a compiled ruleset and answers Match queries.
type Tagger struct {
	rules []*Rule

	// every distinct tag string the loaded ruleset can emit, sorted; used
	// to power the /api/results/tag endpoint.
	allTags []string
}

// New loads the default embedded ruleset.
func New() (*Tagger, error) {
	return load(defaultRules, "embedded rules.yaml")
}

// LoadFromFile loads rules from an external YAML file, falling back to the
// embedded ruleset if path is empty.
func LoadFromFile(path string) (*Tagger, error) {
	if path == "" {
		return New()
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return load(raw, path)
}

func load(raw []byte, source string) (*Tagger, error) {
	var f rulesFile
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", source, err)
	}

	tagSet := map[string]struct{}{}
	for i, r := range f.Rules {
		if r.Name == "" {
			return nil, fmt.Errorf("%s rule %d: missing name", source, i)
		}

		if err := r.compile(); err != nil {
			return nil, fmt.Errorf("%s rule %q: %w", source, r.Name, err)
		}

		if !r.hasMatcher() {
			return nil, fmt.Errorf("%s rule %q: no matcher", source, r.Name)
		}

		for _, t := range r.emittedTags() {
			tagSet[t] = struct{}{}
		}
	}

	allTags := make([]string, 0, len(tagSet))
	for t := range tagSet {
		allTags = append(allTags, t)
	}
	sort.Strings(allTags)

	return &Tagger{rules: f.Rules, allTags: allTags}, nil
}

// Tags returns every distinct tag string the loaded ruleset can emit,
// sorted alphabetically. Useful as a fixed dropdown source for UI
// filters when no scan results exist yet.
func (t *Tagger) Tags() []string { return append([]string(nil), t.allTags...) }

// Match evaluates rules against the input and returns deduped tag names.
// Favicon-hash matchers run first; if any rule matches by favicon, only
// those tags are returned. Otherwise the matcher falls back to the
// title/header/body/tech matchers.
func (t *Tagger) Match(in MatchInput) []string {
	if t == nil || len(t.rules) == 0 {
		return nil
	}

	// pass 1: favicon-hash matchers (only when a favicon was actually
	// fetched and hashed).
	var hits []*Rule
	if in.HasFavicon {
		for _, r := range t.rules {
			for _, h := range r.faviconHashes {
				if h == in.FaviconHash {
					hits = append(hits, r)
					break
				}
			}
		}
	}

	if len(hits) == 0 {
		// pass 2: fallback matchers.
		for _, r := range t.rules {
			if r.matchFallback(in) {
				hits = append(hits, r)
			}
		}
	}

	if len(hits) == 0 {
		return nil
	}

	out := make([]string, 0, len(hits)*3)
	seen := make(map[string]struct{}, len(hits)*3)
	for _, r := range hits {
		for _, t := range r.emittedTags() {
			if _, ok := seen[t]; ok {
				continue
			}
			seen[t] = struct{}{}
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

func (r *Rule) compile() error {
	if !r.FaviconHash.IsZero() {
		switch r.FaviconHash.Kind {
		case yaml.ScalarNode:
			var v int32
			if err := r.FaviconHash.Decode(&v); err != nil {
				return fmt.Errorf("favicon_hash: %w", err)
			}
			r.faviconHashes = []int32{v}
		case yaml.SequenceNode:
			var vs []int32
			if err := r.FaviconHash.Decode(&vs); err != nil {
				return fmt.Errorf("favicon_hash list: %w", err)
			}
			r.faviconHashes = vs
		default:
			return fmt.Errorf("favicon_hash: unsupported yaml kind %d", r.FaviconHash.Kind)
		}
	}

	if r.TitleRegex != "" {
		re, err := regexp.Compile(r.TitleRegex)
		if err != nil {
			return fmt.Errorf("title_regex: %w", err)
		}
		r.titleRegexComp = re
	}

	return nil
}

func (r *Rule) hasMatcher() bool {
	return len(r.faviconHashes) > 0 ||
		r.titleRegexComp != nil ||
		len(r.TitleContains) > 0 ||
		len(r.HeaderContains) > 0 ||
		len(r.BodyContains) > 0 ||
		len(r.TechContains) > 0
}

func (r *Rule) emittedTags() []string {
	var out []string
	if r.Name != "" {
		out = append(out, r.Name)
	}
	if r.Category != "" {
		out = append(out, r.Category)
	}
	if r.Vendor != "" {
		out = append(out, r.Vendor)
	}
	return out
}

func (r *Rule) matchFallback(in MatchInput) bool {
	if r.titleRegexComp != nil && r.titleRegexComp.MatchString(in.Title) {
		return true
	}
	if len(r.TitleContains) > 0 && containsAnyFold(in.Title, r.TitleContains) {
		return true
	}
	if len(r.BodyContains) > 0 && containsAnyFold(in.Body, r.BodyContains) {
		return true
	}
	if len(r.TechContains) > 0 {
		for _, want := range r.TechContains {
			for _, have := range in.Technologies {
				if strings.EqualFold(have, want) {
					return true
				}
			}
		}
	}
	if len(r.HeaderContains) > 0 && headerMatches(in.Headers, r.HeaderContains) {
		return true
	}
	return false
}

func containsAnyFold(haystack string, needles []string) bool {
	if haystack == "" {
		return false
	}
	lower := strings.ToLower(haystack)
	for _, n := range needles {
		if n == "" {
			continue
		}
		if strings.Contains(lower, strings.ToLower(n)) {
			return true
		}
	}
	return false
}

// headerMatches returns true when every entry in want has at least one
// header value that contains the requested substring. Match is
// case-insensitive on both header name and value.
func headerMatches(headers map[string][]string, want map[string]string) bool {
	if len(want) == 0 || len(headers) == 0 {
		return false
	}
	folded := make(map[string][]string, len(headers))
	for k, vs := range headers {
		folded[strings.ToLower(k)] = vs
	}
	for wantKey, wantSub := range want {
		vals, ok := folded[strings.ToLower(wantKey)]
		if !ok {
			return false
		}
		matched := false
		needle := strings.ToLower(wantSub)
		for _, v := range vals {
			if strings.Contains(strings.ToLower(v), needle) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}
