package main

import (
	"strconv"
	"strings"

	"anon-scan/internal/models"
)

// parseStatusList parses "200, 101,403" into []int. Invalid or out-of-range
// entries (outside 100-599) are ignored.
func parseStatusList(s string) []int {
	var out []int
	seen := map[int]bool{}
	for _, part := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || n < 100 || n > 599 || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

// statusMatches reports whether the result's HTTP status is one of the wanted
// codes. An empty list matches everything.
func statusMatches(r models.ScanResult, want []int) bool {
	if len(want) == 0 {
		return true
	}
	for _, c := range want {
		if r.HTTP.StatusCode == c {
			return true
		}
	}
	return false
}
