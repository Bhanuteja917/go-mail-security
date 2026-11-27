package config

import (
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantErr bool
		check   func(t *testing.T, c Config)
	}{
		{name: "missing database url", env: map[string]string{}, wantErr: true},
		{
			name: "defaults",
			env:  map[string]string{"DATABASE_URL": "postgres://x"},
			check: func(t *testing.T, c Config) {
				if c.HTTPAddr != ":8080" || c.ShutdownTimeout != 15*time.Second {
					t.Fatalf("unexpected defaults: %+v", c)
				}
			},
		},
		{
			name: "overrides",
			env:  map[string]string{"DATABASE_URL": "postgres://x", "HTTP_ADDR": ":9000", "SHUTDOWN_TIMEOUT": "3s"},
			check: func(t *testing.T, c Config) {
				if c.HTTPAddr != ":9000" || c.ShutdownTimeout != 3*time.Second {
					t.Fatalf("unexpected config: %+v", c)
				}
			},
		},
		{name: "bad duration", env: map[string]string{"DATABASE_URL": "x", "SHUTDOWN_TIMEOUT": "soon"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, k := range []string{"DATABASE_URL", "HTTP_ADDR", "SHUTDOWN_TIMEOUT", "LOG_LEVEL"} {
				t.Setenv(k, tt.env[k])
			}
			c, err := Load()
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.check != nil {
				tt.check(t, c)
			}
		})
	}
}
