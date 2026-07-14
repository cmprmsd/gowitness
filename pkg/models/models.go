package models

import (
	"time"
)

// RequestType are network log types
type RequestType int

const (
	HTTP RequestType = 0
	WS
)

// Result is a Gowitness result
type Result struct {
	ID uint `json:"id" gorm:"primarykey"`

	URL                   string    `json:"url"`
	URLScheme             string    `json:"url_scheme" gorm:"index"`
	ProbedAt              time.Time `json:"probed_at"`
	FinalURL              string    `json:"final_url"`
	ResponseCode          int       `json:"response_code"`
	ResponseReason        string    `json:"response_reason"`
	Protocol              string    `json:"protocol"`
	ContentLength         int64     `json:"content_length"`
	HTML                  string    `json:"html" gorm:"type:longtext;index:,length:191"`
	Title                 string    `json:"title" gorm:"index"`
	PerceptionHash        string    `json:"perception_hash" gorm:"index"`
	PerceptionHashGroupId uint      `json:"perception_hash_group_id" gorm:"index"`
	Screenshot            string    `json:"screenshot"`

	// Name of the screenshot file
	Filename string `json:"file_name"`
	IsPDF    bool   `json:"is_pdf"`

	// Failed flag set if the result should be considered failed
	Failed       bool   `json:"failed"`
	FailedReason string `json:"failed_reason"`

	// DiscoveredCreds records the credentials (or "anonymous") that
	// successfully authenticated when the driver walked an automatic
	// credential ladder. Empty when the operator supplied creds
	// explicitly via URL or CLI flags, or when the protocol has no auth
	// concept. Currently populated by the RTSP driver.
	DiscoveredCreds string `json:"discovered_creds" gorm:"index"`

	TLS          TLS          `json:"tls" gorm:"constraint:OnDelete:CASCADE"`
	Technologies []Technology `json:"technologies" gorm:"constraint:OnDelete:CASCADE"`
	Tags         []Tag        `json:"tags" gorm:"constraint:OnDelete:CASCADE"`

	Headers []Header     `json:"headers" gorm:"constraint:OnDelete:CASCADE"`
	Network []NetworkLog `json:"network" gorm:"constraint:OnDelete:CASCADE"`
	Console []ConsoleLog `json:"console" gorm:"constraint:OnDelete:CASCADE"`
	Cookies []Cookie     `json:"cookies" gorm:"constraint:OnDelete:CASCADE"`
}

func (r *Result) HeaderMap() map[string][]string {
	headersMap := make(map[string][]string)

	for _, header := range r.Headers {
		headersMap[header.Key] = []string{header.Value}
	}

	return headersMap
}

type TLS struct {
	ID       uint `json:"id" gorm:"primarykey"`
	ResultID uint `json:"resultid"`

	Protocol                 string       `json:"protocol"`
	KeyExchange              string       `json:"key_exchange"`
	Cipher                   string       `json:"cipher"`
	SubjectName              string       `json:"subject_name"`
	SanList                  []TLSSanList `json:"san_list" gorm:"constraint:OnDelete:CASCADE"`
	Issuer                   string       `json:"issuer"`
	ValidFrom                time.Time    `json:"valid_from"`
	ValidTo                  time.Time    `json:"valid_to"`
	ServerSignatureAlgorithm int64        `json:"server_signature_algorithm"`
	EncryptedClientHello     bool         `json:"encrypted_client_hello"`
}

type TLSSanList struct {
	ID    uint `json:"id" gorm:"primarykey"`
	TLSID uint `json:"tls_id"`

	Value string `json:"value"`
}

type Technology struct {
	ID       uint `json:"id" gorm:"primarykey"`
	ResultID uint `json:"result_id"`

	Value string `json:"value" gorm:"index"`
}

// Tag is an operator-friendly classification (e.g. "printer", "fortinet",
// "FortiGate") attached to a Result by the tagger. Multiple Tag rows per
// Result are normal: a single matched rule may emit a product name, its
// category, and its vendor as three separate Tag rows.
//
// Type identifies which axis of the rule the value came from - one of
// "name" (the specific product), "category" (e.g. "printer"), or
// "vendor" (e.g. "canon"). Used by the UI to group the filter dropdown.
type Tag struct {
	ID       uint `json:"id" gorm:"primarykey"`
	ResultID uint `json:"result_id"`

	Value string `json:"value" gorm:"index"`
	Type  string `json:"type" gorm:"index"`
}

type Header struct {
	ID       uint `json:"id" gorm:"primarykey"`
	ResultID uint `json:"result_id"`

	Key   string `json:"key"`
	Value string `json:"value" gorm:"type:longtext;index:,length:191"`
}

type NetworkLog struct {
	ID       uint `json:"id" gorm:"primarykey"`
	ResultID uint `json:"result_id"`

	RequestType RequestType `json:"request_type"`
	StatusCode  int64       `json:"status_code"`
	URL         string      `json:"url"`
	RemoteIP    string      `json:"remote_ip"`
	MIMEType    string      `json:"mime_type"`
	Time        time.Time   `json:"time"`
	Content     []byte      `json:"content"`
	Error       string      `json:"error"`
}

type ConsoleLog struct {
	ID       uint `json:"id" gorm:"primarykey"`
	ResultID uint `json:"result_id"`

	Type  string `json:"type"`
	Value string `json:"value" gorm:"type:longtext;index:,length:191"`
}

type Cookie struct {
	ID       uint `json:"id" gorm:"primarykey"`
	ResultID uint `json:"result_id"`

	Name         string    `json:"name"`
	Value        string    `json:"value"`
	Domain       string    `json:"domain"`
	Path         string    `json:"path"`
	Expires      time.Time `json:"expires"`
	Size         int64     `json:"size"`
	HTTPOnly     bool      `json:"http_only"`
	Secure       bool      `json:"secure"`
	Session      bool      `json:"session"`
	Priority     string    `json:"priority"`
	SourceScheme string    `json:"source_scheme"`
	SourcePort   int64     `json:"source_port"`
}
