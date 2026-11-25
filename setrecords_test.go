// SPDX-License-Identifier: MIT

package glesys

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/libdns/glesys/internal/impl"
	"github.com/libdns/libdns"
)

// fakeZone is a minimal GleSYS DNS API: one zone, records by ID.
type fakeZone struct {
	records []impl.DNSDomainRecord
	nextID  int
	calls   []string
}

func (z *fakeZone) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var params impl.DNSDomainRecord
	_ = json.NewDecoder(r.Body).Decode(&params)
	call := strings.TrimPrefix(r.URL.Path, "/domain/")
	z.calls = append(z.calls, call)
	resp := map[string]any{}
	switch call {
	case "listrecords":
		resp["records"] = z.records
	case "addrecord":
		z.nextID++
		params.RecordID = z.nextID
		z.records = append(z.records, params)
		resp["record"] = params
	case "updaterecord":
		i := slices.IndexFunc(z.records, func(dr impl.DNSDomainRecord) bool { return dr.RecordID == params.RecordID })
		if i < 0 {
			http.Error(w, `{"response":{"status":{"text":"no such record"}}}`, http.StatusNotFound)
			return
		}
		dr := &z.records[i]
		dr.Host, dr.Data, dr.Type = params.Host, params.Data, params.Type
		if params.TTL != 0 {
			dr.TTL = params.TTL
		}
		resp["record"] = *dr
	case "deleterecord":
		z.records = slices.DeleteFunc(z.records, func(dr impl.DNSDomainRecord) bool { return dr.RecordID == params.RecordID })
	default:
		http.Error(w, `{"response":{"status":{"text":"unknown call"}}}`, http.StatusBadRequest)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"response": resp})
}

func (z *fakeZone) rrset(host, typ string) []string {
	out := []string{}
	for _, dr := range z.records {
		if dr.Host == host && dr.Type == typ {
			out = append(out, dr.Data+"/"+time.Duration(dr.TTL*int(time.Second)).String())
		}
	}
	slices.Sort(out)
	return out
}

func newFakeProvider(t *testing.T, z *fakeZone) *Provider {
	srv := httptest.NewServer(z)
	t.Cleanup(srv.Close)
	p := &Provider{Project: "cl00000", APIKey: "test"}
	if err := p.client().SetBaseURL(srv.URL + "/"); err != nil {
		t.Fatal(err)
	}
	return p
}

func a(name, ip string, ttl time.Duration) libdns.Record {
	return libdns.RR{Name: name, Type: "A", Data: ip, TTL: ttl}
}

func TestSetRecordsReplacesRRset(t *testing.T) {
	tests := []struct {
		name      string
		existing  []impl.DNSDomainRecord
		input     []libdns.Record
		wantA     []string
		wantCalls []string
	}{
		{
			name: "new IP replaces the old one",
			existing: []impl.DNSDomainRecord{
				{RecordID: 1, Host: "@", Type: "A", Data: "83.233.22.76", TTL: 60},
				{RecordID: 2, Host: "@", Type: "MX", Data: "mx.example.com.", TTL: 3600},
			},
			input:     []libdns.Record{a("@", "82.209.136.206", time.Minute)},
			wantA:     []string{"82.209.136.206/1m0s"},
			wantCalls: []string{"listrecords", "updaterecord"},
		},
		{
			name:      "TTL-only change updates in place",
			existing:  []impl.DNSDomainRecord{{RecordID: 1, Host: "@", Type: "A", Data: "82.209.136.206", TTL: 3600}},
			input:     []libdns.Record{a("@", "82.209.136.206", time.Minute)},
			wantA:     []string{"82.209.136.206/1m0s"},
			wantCalls: []string{"listrecords", "updaterecord"},
		},
		{
			name:      "unchanged record makes no changes",
			existing:  []impl.DNSDomainRecord{{RecordID: 1, Host: "@", Type: "A", Data: "82.209.136.206", TTL: 60}},
			input:     []libdns.Record{a("@", "82.209.136.206", time.Minute)},
			wantA:     []string{"82.209.136.206/1m0s"},
			wantCalls: []string{"listrecords"},
		},
		{
			name:      "zero TTL ignores the existing TTL",
			existing:  []impl.DNSDomainRecord{{RecordID: 1, Host: "@", Type: "A", Data: "82.209.136.206", TTL: 600}},
			input:     []libdns.Record{a("@", "82.209.136.206", 0)},
			wantA:     []string{"82.209.136.206/10m0s"},
			wantCalls: []string{"listrecords"},
		},
		{
			name: "duplicates left by v1.0.0 are cleaned up",
			existing: []impl.DNSDomainRecord{
				{RecordID: 1, Host: "@", Type: "A", Data: "83.233.22.76", TTL: 60},
				{RecordID: 2, Host: "@", Type: "A", Data: "82.209.136.206", TTL: 3600},
			},
			input:     []libdns.Record{a("@", "82.209.136.206", time.Minute)},
			wantA:     []string{"82.209.136.206/1m0s"},
			wantCalls: []string{"listrecords", "updaterecord", "deleterecord"},
		},
		{
			name:      "missing RRset is added",
			existing:  []impl.DNSDomainRecord{},
			input:     []libdns.Record{a("@", "82.209.136.206", time.Minute)},
			wantA:     []string{"82.209.136.206/1m0s"},
			wantCalls: []string{"listrecords", "addrecord"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			z := &fakeZone{records: tt.existing, nextID: 100}
			p := newFakeProvider(t, z)
			got, err := p.SetRecords(context.Background(), "example.com.", tt.input)
			if err != nil {
				t.Fatal(err)
			}
			if have := z.rrset("@", "A"); !slices.Equal(have, tt.wantA) {
				t.Errorf("A RRset = %v, want %v", have, tt.wantA)
			}
			if !slices.Equal(z.calls, tt.wantCalls) {
				t.Errorf("calls = %v, want %v", z.calls, tt.wantCalls)
			}
			if len(got) != len(tt.input) {
				t.Errorf("returned %d records, want %d", len(got), len(tt.input))
			}
			if mx := z.rrset("@", "MX"); len(tt.existing) > 1 && tt.existing[1].Type == "MX" && len(mx) != 1 {
				t.Errorf("MX RRset touched: %v", mx)
			}
		})
	}
}
