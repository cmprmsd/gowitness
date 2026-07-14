//go:build !cgo

// Stub for CGO_ENABLED=0 builds. The real channel.go uses cgo for unsafe
// channel-buffer manipulation; downstream packages (notably
// protocol/t125/gcc) only need the channel-name string constants below to
// build a static-virtual-channel list during MCS Connect Initial.
//
// Vendored under third_party/grdp/ via go.mod replace because upstream
// has not split CGo from the constants.
package plugin

const (
	CLIPRDR_SVC_CHANNEL_NAME = "cliprdr"
	RDPDR_SVC_CHANNEL_NAME   = "rdpdr"
	RDPSND_SVC_CHANNEL_NAME  = "rdpsnd"
	RAIL_SVC_CHANNEL_NAME    = "rail"
)
