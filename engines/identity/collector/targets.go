/*
rexdr - Active Directory Intelligence Engine
collector/targets.go - Domain controller target loading

Author  : Rayyan Umair
Date    : 2026-06-18
Purpose : Loads targets.yaml and filters to domain controller targets
          only - identified by "DC" in the target name, consistent
          with the naming convention used across the REXDR config.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Trust, but verify the keys."

--- Part of the REXDR platform. ---
*/

package main

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Target struct {
	Name        string `yaml:"name"`
	IP          string `yaml:"ip"`
	Method      string `yaml:"method"`
	Credentials string `yaml:"credentials"`
	Priority    string `yaml:"priority"`
	Enabled     bool   `yaml:"enabled"`
}

type TargetsFile struct {
	Targets []Target `yaml:"targets"`
}

func loadDCTargets(path string) ([]Target, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read targets file - path=%s error=%w", path, err)
	}

	var tf TargetsFile
	if err := yaml.Unmarshal(data, &tf); err != nil {
		return nil, fmt.Errorf("could not parse targets file - path=%s error=%w", path, err)
	}

	var dcTargets []Target
	for _, t := range tf.Targets {
		if t.Enabled && strings.Contains(strings.ToUpper(t.Name), "DC") {
			dcTargets = append(dcTargets, t)
		}
	}

	if len(dcTargets) == 0 {
		return nil, fmt.Errorf("no enabled domain controller targets found in %s", path)
	}

	return dcTargets, nil
}
