// Package config loads service configuration from environment variables.
package config

import (
	"errors"
	"os"
	"time"
)

// Config holds the runtime settings of threat-intel-api.
type Config struct {
	HTTPAddr        string
	DatabaseURL     string
	ShutdownTimeout time.Duration
	LogLevel        string
}

// Load reads configuration from the environment and applies defaults.
func Load() (Config, error) {
	c := Config{
		HTTPAddr:        getenv("HTTP_ADDR", ":8080"),
		DatabaseURL:     os.Getenv("DATABASE_URL"),
		LogLevel:        getenv("LOG_LEVEL", "info"),
		ShutdownTimeout: 15 * time.Second,
	}
	if v := os.Getenv("SHUTDOWN_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, errors.New("SHUTDOWN_TIMEOUT must be a duration such as 10s: " + err.Error())
		}
		c.ShutdownTimeout = d
	}
	if c.DatabaseURL == "" {
		return Config{}, errors.New("DATABASE_URL is required")
	}
	return c, nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
