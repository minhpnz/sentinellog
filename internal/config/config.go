// Package config loads configuration from environment variables (12-factor).
package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	ListenAddr      string        // SL_LISTEN_ADDR
	BufferSize      int           // SL_BUFFER_SIZE    - backpressure ceiling
	BatchSize       int           // SL_BATCH_SIZE     - entries per flush
	BatchInterval   time.Duration // SL_BATCH_INTERVAL - maximum time between flushes
	RatePerTenant   float64       // SL_RATE           - events per second per tenant
	BurstPerTenant  int           // SL_BURST          - token bucket burst allowance
	MaxBodyBytes    int64         // SL_MAX_BODY       - guards against oversized bodies
	ShutdownTimeout time.Duration // SL_SHUTDOWN_TIMEOUT
}

// Load returns a config with sensible development defaults, overridable by env.
func Load() Config {
	return Config{
		ListenAddr:      env("SL_LISTEN_ADDR", ":8080"),
		BufferSize:      envInt("SL_BUFFER_SIZE", 10000),
		BatchSize:       envInt("SL_BATCH_SIZE", 500),
		BatchInterval:   envDur("SL_BATCH_INTERVAL", time.Second),
		RatePerTenant:   envFloat("SL_RATE", 1000),
		BurstPerTenant:  envInt("SL_BURST", 2000),
		MaxBodyBytes:    int64(envInt("SL_MAX_BODY", 1<<20)), // 1 MiB
		ShutdownTimeout: envDur("SL_SHUTDOWN_TIMEOUT", 15*time.Second),
	}
}

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v, ok := os.LookupEnv(k); ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envFloat(k string, def float64) float64 {
	if v, ok := os.LookupEnv(k); ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

func envDur(k string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(k); ok {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
