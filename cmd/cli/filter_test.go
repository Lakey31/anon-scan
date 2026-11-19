package main

import (
	"reflect"
	"testing"

	"anon-scan/internal/models"
)

func TestParseStatusList(t *testing.T) {
	cases := map[string][]int{
		"":              nil,
		"200":           {200},
		"200, 101,403":  {200, 101, 403},
		"200,200,abc,9": {200},
		"600,99,301":    {301},
	}
	for in, want := range cases {
		if got := parseStatusList(in); !reflect.DeepEqual(got, want) {
			t.Errorf("parseStatusList(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestStatusMatches(t *testing.T) {
	var r models.ScanResult
	r.HTTP.StatusCode = 403
	if !statusMatches(r, nil) {
		t.Error("empty filter should match everything")
	}
	if !statusMatches(r, []int{200, 403}) {
		t.Error("403 should match [200 403]")
	}
	if statusMatches(r, []int{200, 101}) {
		t.Error("403 should not match [200 101]")
	}
}
