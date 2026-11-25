// SPDX-FileCopyrightText: 2022 Peter Magnusson <me@kmpm.se>
// SPDX-License-Identifier: MIT
package glesys

import (
	"context"
	"fmt"
	"log"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/libdns/glesys/internal/impl"
	"github.com/libdns/libdns"
)

var debug bool

const _DebugKey_ = "LIBDNS_GLESYS_DEBUG"

func init() {
	if b, err := strconv.ParseBool(os.Getenv(_DebugKey_)); err == nil && b {
		debug = true
	}
}

type Provider struct {
	mutex       sync.Mutex
	clientCache *impl.Client
	Project     string `json:"project,omitempty"`
	APIKey      string `json:"api_key,omitempty"`
}

func (p *Provider) client() *impl.Client {
	if p.clientCache == nil {
		p.clientCache = impl.NewClient(p.Project, p.APIKey, "libdns-glesys/0.0.2")
	}
	return p.clientCache
}

type recordWithMatchingGlesys struct {
	Record  libdns.Record
	Matches []impl.DNSDomainRecord
}

// getMatchingRecords returns records with the matches to the given records.
// It compares the records in the zone with the records in the input.
// Check for .Matches to be empty or not.
func (p *Provider) getMatchingRecords(ctx context.Context, zone string, records []libdns.Record) ([]recordWithMatchingGlesys, error) {
	zone = cleanZ(zone)
	if debug {
		log.Printf("getMatchingRecords zone=%s", zone)
	}
	existingRecords, err := p.client().DNSDomains.ListRecords(ctx, zone)
	if err != nil {
		return nil, err
	}
	results := []recordWithMatchingGlesys{}
	for _, r := range records {
		rr := r.RR()
		matches := []impl.DNSDomainRecord{}
		for _, dr := range *existingRecords {
			hasMatching := checkParamsMatching(rr, &dr)
			if !hasMatching.all() {
				continue
			}
			matches = append(matches, dr)
		}
		results = append(results, recordWithMatchingGlesys{Record: r, Matches: matches})
	}
	if debug {
		log.Printf("getMatchingRecords result: %+v", results)
	}
	return results, nil
}

type recordWithMatchingLibDNS struct {
	Record  impl.DNSDomainRecord
	Matches []libdns.Record
}

func (p *Provider) getMatchingRecordsLibDNS(ctx context.Context, zone string, records []libdns.Record) ([]recordWithMatchingLibDNS, error) {
	zone = cleanZ(zone)
	if debug {
		log.Printf("getMatchingRecordsLibDNS zone=%s", zone)
	}
	existingRecords, err := p.client().DNSDomains.ListRecords(ctx, zone)
	if err != nil {
		return nil, err
	}
	results := []recordWithMatchingLibDNS{}
	for _, dr := range *existingRecords {
		matches := []libdns.Record{}
		for _, r := range records {
			rr := r.RR()
			hasMatching := checkParamsMatching(rr, &dr)
			if !hasMatching.all() {
				continue
			}
			matches = append(matches, r)
		}
		results = append(results, recordWithMatchingLibDNS{Record: dr, Matches: matches})
	}
	if debug {
		log.Printf("getMatchingRecordsLibDNS result: %+v", results)
	}
	return results, nil
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	zone = cleanZ(zone)
	if debug {
		log.Printf("GetRecords zone=%s", zone)
	}
	drs, err := p.client().DNSDomains.ListRecords(ctx, zone)
	if err != nil {
		return nil, err
	}
	records := make([]libdns.Record, len(*drs))
	for i, dr := range *drs {
		if zone != dr.DomainName {
			return records, fmt.Errorf("unexpected domainname in respose: %v", dr.DomainName)
		}
		r, err := toLibDNS(&dr)
		if err != nil {
			return nil, err
		}
		records[i] = r
	}
	if debug {
		log.Printf("GetRecords result: %+v", records)
	}
	return records, nil

}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	zone = cleanZ(zone)
	if debug {
		log.Printf("AppendRecords zone=%s", zone)
	}
	results := []libdns.Record{}
	for _, r := range records {
		rr := r.RR()
		param := impl.AddRecordParams{
			DomainName: zone,
			Host:       rr.Name,
			Data:       rr.Data,
			TTL:        int(rr.TTL / time.Second),
			Type:       strings.ToUpper(rr.Type),
		}
		// if r.Priority > 0 {
		// 	param.Data = fmt.Sprintf("%d %s", r.Priority, param.Data)
		// }

		dr, err := p.client().DNSDomains.AddRecord(ctx, param)
		if err != nil {
			return results, err
		}
		if rr, err := toLibDNS(dr); err != nil {
			return results, err
		} else {
			results = append(results, rr)
		}
	}
	if debug {
		log.Printf("AppendRecords result: %+v", results)
	}
	return results, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// In RFC 9499 terms, SetRecords appends, modifies, or deletes records in the
// zone so that for each RRset in the input, the records provided in the input
// are the only members of their RRset in the output zone.
//
// An RRset is matched on name and type only: existing members with other data
// or TTL are updated in place (keeping their record ID), surplus members are
// deleted and missing ones added. The GleSYS API has no transactions, so a
// failure part-way leaves the changes made so far.
// It returns the records now in the zone for the input RRsets.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	zone = cleanZ(zone)
	if debug {
		log.Printf("SetRecords zone=%s", zone)
	}

	existing, err := p.client().DNSDomains.ListRecords(ctx, zone)
	if err != nil {
		return nil, err
	}

	// group the input by RRset, keeping the input order
	type rrset struct {
		name, typ string
		wanted    []libdns.RR
	}
	sets := []*rrset{}
	byKey := map[string]*rrset{}
	for _, r := range records {
		rr := r.RR()
		typ := strings.ToUpper(rr.Type)
		key := rr.Name + " " + typ
		s, ok := byKey[key]
		if !ok {
			s = &rrset{name: rr.Name, typ: typ}
			byKey[key] = s
			sets = append(sets, s)
		}
		s.wanted = append(s.wanted, rr)
	}

	result := []libdns.Record{}
	for _, s := range sets {
		current := []impl.DNSDomainRecord{}
		for _, dr := range *existing {
			if dr.Host == s.name && strings.ToUpper(dr.Type) == s.typ {
				current = append(current, dr)
			}
		}

		// members already as wanted stay untouched
		todo := []libdns.RR{}
		for _, rr := range s.wanted {
			i := slices.IndexFunc(current, func(dr impl.DNSDomainRecord) bool {
				return dr.Data == rr.Data && (rr.TTL == 0 || rr.TTL == time.Duration(dr.TTL)*time.Second)
			})
			if i < 0 {
				todo = append(todo, rr)
				continue
			}
			result = append(result, mustToLibDNS(&current[i]))
			current = slices.Delete(current, i, i+1)
		}

		// reuse the remaining members for the rest, add when none are left
		for _, rr := range todo {
			ttl := int(rr.TTL / time.Second)
			if len(current) > 0 {
				dr := current[0]
				current = current[1:]
				_, err := p.client().DNSDomains.UpdateRecord(ctx, impl.UpdateRecordParams{
					RecordID: dr.RecordID,
					Host:     s.name,
					Data:     rr.Data,
					TTL:      ttl,
					Type:     s.typ,
				})
				if err != nil {
					return result, err
				}
				if ttl == 0 {
					ttl = dr.TTL
				}
			} else {
				_, err := p.client().DNSDomains.AddRecord(ctx, impl.AddRecordParams{
					DomainName: zone,
					Host:       s.name,
					Data:       rr.Data,
					TTL:        ttl,
					Type:       s.typ,
				})
				if err != nil {
					return result, err
				}
			}
			result = append(result, mustToLibDNS(&impl.DNSDomainRecord{
				DomainName: zone,
				Host:       s.name,
				Data:       rr.Data,
				TTL:        ttl,
				Type:       s.typ,
			}))
		}

		// members not in the input leave the RRset
		for _, dr := range current {
			if err := p.client().DNSDomains.DeleteRecord(ctx, dr.RecordID); err != nil {
				return result, err
			}
		}
	}
	return result, nil
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	zone = cleanZ(zone)
	if debug {
		log.Printf("DeleteRecords zone=%s", zone)
	}
	matching, err := p.getMatchingRecords(ctx, zone, records)
	if err != nil {
		return nil, err
	}
	results := []libdns.Record{}
	for _, m := range matching {
		for _, dr := range m.Matches {
			err = p.client().DNSDomains.DeleteRecord(ctx, dr.RecordID)
			if err != nil {
				return results, err
			}
			r, err := toLibDNS(&dr)
			if err != nil {
				return results, err
			}
			results = append(results, r)
		}
	}
	if debug {
		log.Printf("DeleteRecords results: %+v", results)
	}
	return results, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
