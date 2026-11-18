package quic

import (
	"bytes"
	"testing"
)

// TestActualSendBPS 钉住 hysteria2 的取较小值。
//
// 三个分支都来自 hysteria2/client.go：对端 0、对端更大、对端更小。
func TestActualSendBPS(t *testing.T) {
	const up = 125_000_000 // 1 Gbps
	cases := []struct {
		name   string
		peerRx uint64
		want   uint64
	}{
		{"对端没报", 0, up},
		{"对端比本端大", up * 2, up},
		{"对端比本端小", 12_500_000, 12_500_000},
		{"两边一样", up, up},
	}
	for _, c := range cases {
		if got := actualSendBPS(up, c.peerRx); got != c.want {
			t.Errorf("%s: got %d want %d", c.name, got, c.want)
		}
	}
}

// TestBandwidthFrameRoundTrip 钉住帧能原样读回，版本错了要拒绝。
func TestBandwidthFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := writeBandwidth(&buf, 12_500_000); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != bwFrameSize {
		t.Fatalf("帧长 %d，应为 %d", buf.Len(), bwFrameSize)
	}
	got, err := readBandwidth(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got != 12_500_000 {
		t.Fatalf("读回 %d", got)
	}

	bad := []byte{9, 0, 0, 0, 0, 0, 0, 0, 1}
	if _, err := readBandwidth(bytes.NewReader(bad)); err == nil {
		t.Fatal("不认识的版本必须报错")
	}
}
