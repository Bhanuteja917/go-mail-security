package intel

import "testing"

func TestNormalize(t *testing.T) {
	tests := []struct {
		name    string
		kind    Kind
		in      string
		want    string
		wantErr bool
	}{
		{"domain lowercased and dot trimmed", KindDomain, "  Evil.Example.COM. ", "evil.example.com", false},
		{"domain with path rejected", KindDomain, "evil.com/login", "", true},
		{"domain without dot rejected", KindDomain, "localhost", "", true},
		{"ipv4", KindIP, "203.0.113.7", "203.0.113.7", false},
		{"ipv6 canonical", KindIP, "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1", false},
		{"bad ip", KindIP, "999.1.1.1", "", true},
		{"url host lowercased fragment dropped", KindURL, "HTTP://Evil.COM/a?b=1#frag", "http://evil.com/a?b=1", false},
		{"url without scheme rejected", KindURL, "evil.com/a", "", true},
		{"ftp url rejected", KindURL, "ftp://evil.com/a", "", true},
		{"empty", KindURL, "  ", "", true},
		{"unknown kind", Kind("hash"), "abc", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Normalize(tt.kind, tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
