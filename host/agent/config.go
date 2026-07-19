package main

import (
	"encoding/json"
	"fmt"
	"os"
)

const (
	cfgPath  = "bpf-config.json"
	maxPaths = 64
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

type eventFilterConfig struct {
	SuccessfulOnly    bool     `json:"successful_only"`
	WriteOnly         bool     `json:"write_only"`
	FollowAll         bool     `json:"follow_all"`
	FollowOnlyInclude bool     `json:"follow_only_include"`
	FollowOnlyExclude bool     `json:"follow_only_exclude"`
	IncludePaths      []string `json:"include_paths"`
	ExcludePaths      []string `json:"exclude_paths"`
}

type filterConfig struct {
	SuccessfulOnly bool              `json:"successful_only"`
	TCP            eventFilterConfig `json:"tcp"`
	Open           eventFilterConfig `json:"open"`
	Execve         eventFilterConfig `json:"execve"`
	Rename         eventFilterConfig `json:"rename"`
	Chmod          eventFilterConfig `json:"chmod"`
	Unlink         eventFilterConfig `json:"unlink"`
	Clone          eventFilterConfig `json:"clone"`
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

	filters := []*eventFilterConfig{
		&cfg.Filters.TCP,
		&cfg.Filters.Open,
		&cfg.Filters.Execve,
		&cfg.Filters.Rename,
		&cfg.Filters.Chmod,
		&cfg.Filters.Unlink,
		&cfg.Filters.Clone,
	}
	for _, filter := range filters {
		truncateFilterPaths(filter)
	}

	return nil
}

func truncateFilterPaths(filter *eventFilterConfig) {
	if len(filter.IncludePaths) > maxPaths {
		filter.IncludePaths = filter.IncludePaths[:maxPaths]
	}
	if len(filter.ExcludePaths) > maxPaths {
		filter.ExcludePaths = filter.ExcludePaths[:maxPaths]
	}

	for i, path := range filter.IncludePaths {
		if len(path) >= maxPathLen {
			filter.IncludePaths[i] = path[:maxPathLen-1]
		}
	}
	for i, path := range filter.ExcludePaths {
		if len(path) >= maxPathLen {
			filter.ExcludePaths[i] = path[:maxPathLen-1]
		}
	}
}
