// Package oui resolves MAC address prefixes to manufacturers.
//
// The embedded registry (oui.txt.gz) is generated from the IEEE MA-L public
// listing as packaged by the BSD-2-Clause "oui-data" project. Operators can
// override it with a newer IEEE oui.csv via NEXUS_OUI_FILE.
package oui

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/csv"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/vendors"
)

//go:embed oui.txt.gz
var embedded []byte

// Entry is a resolved manufacturer.
type Entry struct {
	Prefix       string `json:"prefix"`
	Organization string `json:"organization"` // registry name
	Vendor       string `json:"vendor"`       // normalized short name
}

var (
	once sync.Once
	db   map[string]string
)

func load() {
	db = make(map[string]string, 45000)
	if f := os.Getenv("NEXUS_OUI_FILE"); f != "" {
		if fh, err := os.Open(f); err == nil {
			loadCSV(fh)
			fh.Close()
			if len(db) > 0 {
				return
			}
		}
	}
	zr, err := gzip.NewReader(bytes.NewReader(embedded))
	if err != nil {
		return
	}
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "\t")
		if ok {
			db[k] = v
		}
	}
}

// loadCSV reads IEEE oui.csv (Registry,Assignment,Organization Name,Address).
func loadCSV(r io.Reader) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	for {
		rec, err := cr.Read()
		if err != nil {
			break
		}
		if len(rec) >= 3 && len(rec[1]) == 6 {
			db[strings.ToLower(rec[1])] = strings.TrimSpace(rec[2])
		}
	}
}

// Lookup resolves a normalized MAC (aa:bb:cc:dd:ee:ff).
func Lookup(mac string) (Entry, bool) {
	once.Do(load)
	p := strings.ReplaceAll(strings.ToLower(mac), ":", "")
	if len(p) < 6 {
		return Entry{}, false
	}
	p = p[:6]
	org, ok := db[p]
	if !ok {
		return Entry{Prefix: p}, false
	}
	return Entry{Prefix: p, Organization: org, Vendor: vendors.NormalizeVendor(org)}, true
}

// IsLocallyAdministered reports whether the MAC is randomized/locally assigned
// (e.g. mobile privacy MACs, many VMs). Such MACs have no manufacturer.
func IsLocallyAdministered(mac string) bool {
	p := strings.ReplaceAll(mac, ":", "")
	if len(p) < 2 {
		return false
	}
	var b byte
	for _, c := range p[:2] {
		b <<= 4
		switch {
		case c >= '0' && c <= '9':
			b |= byte(c - '0')
		case c >= 'a' && c <= 'f':
			b |= byte(c-'a') + 10
		case c >= 'A' && c <= 'F':
			b |= byte(c-'A') + 10
		}
	}
	return b&0x02 != 0
}

// Size returns the number of loaded prefixes.
func Size() int {
	once.Do(load)
	return len(db)
}
