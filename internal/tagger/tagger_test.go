package tagger

import (
	"reflect"
	"sort"
	"testing"
)

func mustLoad(t *testing.T, yaml string) *Tagger {
	t.Helper()
	tg, err := load([]byte(yaml), "test")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return tg
}

// values extracts the .Value field from a Match result for tests that
// only care about which strings were emitted.
func values(tvs []TaggedValue) []string {
	out := make([]string, 0, len(tvs))
	for _, tv := range tvs {
		out = append(out, tv.Value)
	}
	return out
}

func TestEmbeddedDefaultRulesLoad(t *testing.T) {
	tg, err := New()
	if err != nil {
		t.Fatalf("default rules: %v", err)
	}
	if len(tg.Tags()) == 0 {
		t.Fatalf("expected at least one tag in the default ruleset")
	}
}

func TestFaviconHashTakesPrecedenceOverTitle(t *testing.T) {
	tg := mustLoad(t, `
rules:
  - name: "Acme Printer"
    category: "printer"
    vendor: "acme"
    favicon_hash: 12345
  - name: "Title Match"
    category: "anything"
    title_contains: ["acme"]
`)
	got := values(tg.Match(MatchInput{
		FaviconHash: 12345,
		HasFavicon:  true,
		Title:       "Welcome to Acme",
	}))
	want := []string{"Acme Printer", "acme", "printer"}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("favicon precedence: got %v want %v", got, want)
	}
}

func TestFaviconHashEmitsType(t *testing.T) {
	tg := mustLoad(t, `
rules:
  - name: "Acme"
    category: "printer"
    vendor: "acme"
    favicon_hash: 12345
`)
	got := tg.Match(MatchInput{FaviconHash: 12345, HasFavicon: true})
	want := []TaggedValue{
		{Value: "Acme", Type: TypeName},
		{Value: "acme", Type: TypeVendor},
		{Value: "printer", Type: TypeCategory},
	}
	sort.Slice(want, func(i, j int) bool { return want[i].Value < want[j].Value })
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("typed match: got %v want %v", got, want)
	}
}

func TestTitleFallbackUsedWhenNoFaviconHashHits(t *testing.T) {
	tg := mustLoad(t, `
rules:
  - name: "Acme Firewall"
    category: "firewall"
    vendor: "acme"
    favicon_hash: 99999
  - name: "Title Match"
    category: "router"
    title_contains: ["UniFi"]
`)
	got := values(tg.Match(MatchInput{
		FaviconHash: 12345, // no rule matches this
		HasFavicon:  true,
		Title:       "UniFi Controller",
	}))
	want := []string{"Title Match", "router"}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("title fallback: got %v want %v", got, want)
	}
}

func TestTitleRegexCaseInsensitive(t *testing.T) {
	tg := mustLoad(t, `
rules:
  - name: "VMware vSphere"
    category: "hypervisor"
    vendor: "vmware"
    title_regex: "(?i)vsphere|vcenter"
`)
	in := MatchInput{Title: "VSPHERE Web Client"}
	got := values(tg.Match(in))
	want := []string{"VMware vSphere", "hypervisor", "vmware"}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("regex match: got %v want %v", got, want)
	}
}

func TestHeaderMatchersAreCaseFolded(t *testing.T) {
	tg := mustLoad(t, `
rules:
  - name: "FortiGate"
    category: "firewall"
    vendor: "fortinet"
    header_contains:
      Server: "xxxxxxxx"
`)
	got := values(tg.Match(MatchInput{
		Headers: map[string][]string{"server": {"xXxxxxxX-1.0"}},
	}))
	want := []string{"FortiGate", "firewall", "fortinet"}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("header match: got %v want %v", got, want)
	}
}

func TestTechMatcher(t *testing.T) {
	tg := mustLoad(t, `
rules:
  - name: "Jenkins"
    category: "devops"
    vendor: "jenkins"
    tech_contains: ["Jenkins"]
`)
	got := values(tg.Match(MatchInput{Technologies: []string{"jenkins"}}))
	want := []string{"Jenkins", "devops", "jenkins"}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tech match: got %v want %v", got, want)
	}
}

func TestMultipleHashesPerRule(t *testing.T) {
	tg := mustLoad(t, `
rules:
  - name: "Multi"
    favicon_hash:
      - 1
      - 2
      - 3
`)
	for _, h := range []int32{1, 2, 3} {
		got := values(tg.Match(MatchInput{FaviconHash: h, HasFavicon: true}))
		if !reflect.DeepEqual(got, []string{"Multi"}) {
			t.Fatalf("hash %d: got %v", h, got)
		}
	}
	if got := tg.Match(MatchInput{FaviconHash: 4, HasFavicon: true}); got != nil {
		t.Fatalf("non-matching hash should miss favicon pass; got %v", got)
	}
}

func TestNoMatchersIsRejected(t *testing.T) {
	if _, err := load([]byte(`
rules:
  - name: "Empty"
`), "t"); err == nil {
		t.Fatal("expected error for rule with no matchers")
	}
}

func TestDuplicateTagsAreDeduped(t *testing.T) {
	tg := mustLoad(t, `
rules:
  - name: "Same"
    category: "x"
    vendor: "y"
    favicon_hash: 1
  - name: "Same"
    category: "x"
    vendor: "y"
    favicon_hash: 1
`)
	got := values(tg.Match(MatchInput{FaviconHash: 1, HasFavicon: true}))
	want := []string{"Same", "x", "y"}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("dedup: got %v want %v", got, want)
	}
}

func TestShodanHashKnownVector(t *testing.T) {
	// Cross-checked against Python:
	//   import mmh3, base64
	//   mmh3.hash(base64.encodebytes(b"abc").decode())  # -868969266
	got, err := ShodanHash([]byte("abc"))
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	const want int32 = -868969266
	if got != want {
		t.Fatalf("ShodanHash(abc) = %d, want %d", got, want)
	}
}
