package flowtls

import (
	"bytes"
	"os"
	"testing"
)

func TestMasqueradeDefaultPageUsesEmbeddedIndex(t *testing.T) {
	expected, err := os.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}

	status, body, contentType := (&masquerade{}).route("GET", "/")
	if status != "200 OK" {
		t.Fatalf("unexpected status: %s", status)
	}
	if contentType != "text/html; charset=utf-8" {
		t.Fatalf("unexpected content type: %s", contentType)
	}
	if !bytes.Equal(body, expected) {
		t.Fatal("default page does not match web/index.html")
	}
}
