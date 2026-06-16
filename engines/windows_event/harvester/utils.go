/*
rexdr - Windows Event Intelligence Engine
harvester/utils.go - Utility functions for the harvester

Author  : Rayyan Umair
Date    : 2026-06-12
Purpose : Shared utility functions used across the harvester.
          Environment variable helpers with typed defaults.
          Nothing domain-specific lives here.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Every log tells a story."

--- Part of the REXDR platform. ---
*/

package main

import (
	"os"
	"strconv"
)

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultVal
}

func getEnvBool(key string, defaultVal bool) bool {
	if val := os.Getenv(key); val != "" {
		if b, err := strconv.ParseBool(val); err == nil {
			return b
		}
	}
	return defaultVal
}
