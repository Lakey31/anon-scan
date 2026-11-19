package recon

import "testing"

func TestExpandCIDR(t *testing.T) {
	ips, err := ExpandCIDR("104.16.0.0/29", 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 6 {
		t.Fatalf("expected 6 usable hosts in /29, got %d", len(ips))
	}
	if ips[0] != "104.16.0.1" || ips[5] != "104.16.0.6" {
		t.Fatalf("unexpected IP range bounds: %v", ips)
	}

	// /32 single IP
	single, err := ExpandCIDR("1.1.1.1/32", 10)
	if err != nil || len(single) != 1 || single[0] != "1.1.1.1" {
		t.Fatalf("expected [1.1.1.1] for /32, got %v (err=%v)", single, err)
	}

	// Exceeding maxIPs guard
	if _, err := ExpandCIDR("10.0.0.0/8", 1024); err == nil {
		t.Fatalf("expected error when CIDR exceeds maxIPs limit")
	}
}

func TestCheckDanglingCNAME(t *testing.T) {
	risk := CheckDanglingCNAME("old-app.github.io", nil, "no such host")
	if risk == "" {
		t.Fatalf("expected dangling CNAME warning for github.io with no IPs")
	}

	safe := CheckDanglingCNAME("app.github.io", []string{"185.199.108.153"}, "")
	if safe != "" {
		t.Fatalf("expected empty risk when IP resolves, got %q", safe)
	}
}

func TestIsFakeOrPrivateIP(t *testing.T) {
	cases := map[string]bool{
		"198.19.208.60":  true,
		"198.18.0.1":     true,
		"10.0.0.5":       true,
		"192.168.1.1":    true,
		"127.0.0.1":      true,
		"104.16.132.229": false,
		"1.1.1.1":        false,
		"not-an-ip":      false,
	}
	for ip, want := range cases {
		if got := IsFakeOrPrivateIP(ip); got != want {
			t.Errorf("IsFakeOrPrivateIP(%q) = %v, want %v", ip, got, want)
		}
	}
}
