package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"time"
)

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("htmltrust-key status", flag.ContinueOnError)
	live := fs.String("live", "", "fetch a live signed page and report the period its keyid names")
	if err := fs.Parse(args); err != nil {
		return err
	}

	id, err := LoadIdentity(IdentityStatePath)
	if err != nil {
		return fmt.Errorf("status: %w", err)
	}

	fmt.Printf("identity:          %s\n", id.Identity)
	fmt.Printf("periodScheme:      %s\n", id.PeriodScheme)
	fmt.Printf("periodLength:      %s\n", id.PeriodLength)
	fmt.Printf("signingAnchor:     %s\n", id.SigningAnchor)
	fmt.Printf("derivedThrough:    %d\n", id.DerivedThrough)
	fmt.Printf("publishedThrough:  %d\n", id.PublishedThrough)

	epochTime, epochErr := time.Parse(time.RFC3339, id.PeriodEpoch)
	dur, durErr := parseISODuration(id.PeriodLength)
	if epochErr == nil && durErr == nil {
		if id.DerivedThrough >= 1 {
			start, end := periodWindow(epochTime, dur, id.DerivedThrough)
			fmt.Printf("current period %d nominal window: %s .. %s\n", id.DerivedThrough, start.Format("2006-01-02"), end.Format("2006-01-02"))
		}
		_, publishedEnd := periodWindow(epochTime, dur, id.PublishedThrough)
		fmt.Printf("published buffer runs out around: %s (extend before then)\n", publishedEnd.Format("2006-01-02"))
	}

	if *live != "" {
		period, keyid, err := findLiveKeyid(*live)
		if err != nil {
			fmt.Fprintf(os.Stderr, "status: --live %s: %v\n", *live, err)
		} else {
			fmt.Printf("live page keyid:   %s (period %s)\n", keyid, period)
		}
	}
	return nil
}

// addISODuration adds an ISO 8601 duration to t using calendar (not fixed
// day-count) arithmetic, so a P1M period lands on the same day of the
// following month.
func addISODuration(t time.Time, d isoDuration) time.Time {
	return t.AddDate(d.Years, d.Months, d.Days+d.Weeks*7)
}

// periodWindow returns the nominal [start, end) calendar window of period n
// (spec §9.10: display/tooling metadata only, never a cryptographic
// boundary).
func periodWindow(epoch time.Time, length isoDuration, n int) (start, end time.Time) {
	mul := func(d isoDuration, k int) isoDuration {
		return isoDuration{Years: d.Years * k, Months: d.Months * k, Weeks: d.Weeks * k, Days: d.Days * k}
	}
	start = addISODuration(epoch, mul(length, n-1))
	end = addISODuration(epoch, mul(length, n))
	return start, end
}

var keyidAttrRe = regexp.MustCompile(`keyid="([^"]*)"`)
var periodSuffixRe = regexp.MustCompile(`#p([1-9][0-9]{0,9})$`)

// findLiveKeyid fetches url and returns the first signed-section keyid
// attribute value it finds and the period it names ("(anchor)" if none).
func findLiveKeyid(url string) (period, keyid string, err error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return "", "", err
	}
	m := keyidAttrRe.FindSubmatch(body)
	if m == nil {
		return "", "", fmt.Errorf("no signed-section keyid attribute found")
	}
	keyid = string(m[1])
	if pm := periodSuffixRe.FindStringSubmatch(keyid); pm != nil {
		return pm[1], keyid, nil
	}
	return "(anchor)", keyid, nil
}
