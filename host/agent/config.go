package main

import (
	"encoding/json"
	"fmt"
	"os"
)

const (
	cfgPath    = "bpf-config.json"
	maxPaths   = 64
)

type eventConfig struct {
	TCP    bool `json:"tcp"`
	Open   bool `json:"open"`
	Execve bool `json:"execve"`
	Rename bool `json:"rename"`
	Chmod  bool `json:"chmod"`
	Unlink bool `json:"unlink"`
	Clone  bool `json:"clone"`
}

type openFilterConfig struct {
	WriteOnly bool `json:"write_only"`
}

type filterConfig struct {
	SuccessfulOnly    bool             `json:"successful_only"`
	Open              openFilterConfig `json:"open"`
	FollowOnlyInclude bool             `json:"follow_only_include"`
	FollowOnlyExclude bool             `json:"follow_only_exclude"`
	IncludePaths      []string         `json:"include_paths"`
	ExcludePaths      []string         `json:"exclude_paths"`
}

type config struct {
	Events  eventConfig  `json:"events"`
	Filters filterConfig `json:"filters"`
}

func parseConfig(cfg *config) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return fmt.Errorf("failed to read config %s: %w", cfgPath, err)
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return fmt.Errorf("JSON parse error: %w", err)
	}

	if len(cfg.Filters.IncludePaths) > maxPaths {
		cfg.Filters.IncludePaths = cfg.Filters.IncludePaths[:maxPaths]
	}

	if len(cfg.Filters.ExcludePaths) > maxPaths {
		cfg.Filters.ExcludePaths = cfg.Filters.ExcludePaths[:maxPaths]
	}

	for i, path := range cfg.Filters.IncludePaths {
		if len(path) >= maxPathLen {
			cfg.Filters.IncludePaths[i] = path[:maxPathLen-1]
		}
	}

	for i, path := range cfg.Filters.ExcludePaths {
		if len(path) >= maxPathLen {
			cfg.Filters.ExcludePaths[i] = path[:maxPathLen-1]
		}
	}

	return nil
}