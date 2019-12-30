package storage

import (
	"sort"
	"testing"

	"github.com/cloudflare/certmgr/file"
)

func TestFileBackendPaths(t *testing.T) {
	assert := func(desired, received []string) {
		sort.Strings(desired)
		sort.Strings(received)

		if len(received) != len(desired) {
			t.Fatalf("%s != %s", desired, received)
		}
		for idx := range received {
			if desired[idx] != received[idx] {
				t.Fatalf("%s != %s", desired, received)
			}
		}
	}

	fb := FileBackend{}

	// ensure that an empty spec doesn't trigger a panic
	assert([]string{}, fb.GetPaths())
	fb.ca = &file.CertificateFile{file.File{Path: "/ca"}}

	assert([]string{"/ca"}, fb.GetPaths())
	fb.cert = &file.CertificateFile{file.File{Path: "/cert"}}
	fb.key = &file.File{Path: "/key"}

	assert([]string{"/ca", "/key", "/cert"}, fb.GetPaths())

	fb.ca = nil
	assert([]string{"/key", "/cert"}, fb.GetPaths())
}
