/*
rexdr - Windows Event Intelligence Engine
harvester/targets.go - Target configuration loading

Author  : Rayyan Umair
Date    : 2026-06-12
Purpose : Loads and parses the targets.yaml configuration file.
          Defines the Target struct and all target priority tiers.
          Nothing outside this file reads targets.yaml directly.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Every log tells a story."

--- Part of the REXDR platform. ---
*/

package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ============================================================================
// Target definition
// ============================================================================

type Target struct {
	Name        string   `yaml:"name"`
	IP          string   `yaml:"ip"`
	Method      string   `yaml:"method"`
	Credentials string   `yaml:"credentials"`
	Logs        []string `yaml:"logs"`
	Priority    string   `yaml:"priority"`
	Enabled     bool     `yaml:"enabled"`
}

type TargetsFile struct {
	Targets []Target `yaml:"targets"`
}

// ============================================================================
// Loader
// ============================================================================

func loadTargets(path string) ([]Target, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read targets file - path=%s error=%w", path, err)
	}

	var tf TargetsFile
	if err := yaml.Unmarshal(data, &tf); err != nil {
		return nil, fmt.Errorf("could not parse targets file - path=%s error=%w", path, err)
	}

	// Filter to enabled targets only
	var enabled []Target
	for _, t := range tf.Targets {
		if t.Enabled {
			// Default priority to normal if not set
			if t.Priority == "" {
				t.Priority = "normal"
			}
			// Default method to winrm if not set
			if t.Method == "" {
				t.Method = "winrm"
			}
			// Default logs if not set
			if len(t.Logs) == 0 {
				t.Logs = []string{"Security", "System", "Application"}
			}
			enabled = append(enabled, t)
		}
	}

	if len(enabled) == 0 {
		return nil, fmt.Errorf("no enabled targets found in %s", path)
	}

	return enabled, nil
}
