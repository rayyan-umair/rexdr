/*
rexdr - Windows Event Intelligence Engine
harvester/main.go - Go harvester entry point

Author  : Rayyan Umair
Date    : 2026-06-12
Purpose : Entry point for the REXDR Windows Event harvester.
          Reads targets.yaml, initializes the connection pool,
          and starts collection goroutines for each target.
          Events are written as JSON to stdout where the Python
          brain reads them via subprocess pipe.
          Each target runs on its own goroutine with its own
          collection interval based on priority tier.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Every log tells a story."

--- Part of the REXDR platform. ---
*/

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// ============================================================================
// Entry point
// ============================================================================

func main() {
	log.SetOutput(os.Stderr)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmsgprefix)
	log.SetPrefix("[REXDR-HARVESTER] ")

	log.Println("=== REXDR Windows Event Harvester starting ===")

	// Load configuration from environment
	cfg := loadConfig()

	// Load targets from targets.yaml
	targets, err := loadTargets(cfg.TargetsPath)
	if err != nil {
		log.Fatalf("Failed to load targets - path=%s error=%v", cfg.TargetsPath, err)
	}

	log.Printf("Targets loaded - count=%d", len(targets))

	// Initialize the semaphore to limit concurrent WinRM connections
	sem := make(chan struct{}, cfg.MaxConcurrentWinRM)

	// Wait group for all target goroutines
	var wg sync.WaitGroup

	// Shutdown channel
	shutdown := make(chan struct{})

	// Start a collection goroutine for each target
	for _, target := range targets {
		wg.Add(1)
		go func(t Target) {
			defer wg.Done()
			runTargetCollector(t, cfg, sem, shutdown)
		}(target)
	}

	log.Printf("=== Harvester running - targets=%d ===", len(targets))

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutdown signal received - stopping collectors")
	close(shutdown)
	wg.Wait()
	log.Println("=== REXDR Windows Event Harvester stopped ===")
}

// ============================================================================
// Config
// ============================================================================

type HarvesterConfig struct {
	TargetsPath        string
	Username           string
	Password           string
	WinRMPort          int
	UseSSL             bool
	MaxConcurrentWinRM int
	MaxEventsPerCycle  int
	IntervalCritical   time.Duration
	IntervalHigh       time.Duration
	IntervalNormal     time.Duration
}

func loadConfig() HarvesterConfig {
	return HarvesterConfig{
		TargetsPath:        getEnv("WINRM_TARGETS_PATH", "/config/targets.yaml"),
		Username:           getEnv("WINRM_USERNAME", ""),
		Password:           getEnv("WINRM_PASSWORD", ""),
		WinRMPort:          getEnvInt("WINRM_PORT", 5985),
		UseSSL:             getEnvBool("WINRM_USE_SSL", false),
		MaxConcurrentWinRM: getEnvInt("WINRM_MAX_CONCURRENT", 10),
		MaxEventsPerCycle:  getEnvInt("MAX_EVENTS_PER_COLLECTION", 1000),
		IntervalCritical:   time.Duration(getEnvInt("COLLECTION_INTERVAL_CRITICAL", 60)) * time.Second,
		IntervalHigh:       time.Duration(getEnvInt("COLLECTION_INTERVAL_HIGH", 180)) * time.Second,
		IntervalNormal:     time.Duration(getEnvInt("COLLECTION_INTERVAL_NORMAL", 300)) * time.Second,
	}
}

// ============================================================================
// Target collector
// ============================================================================

func runTargetCollector(
	target Target,
	cfg HarvesterConfig,
	sem chan struct{},
	shutdown chan struct{},
) {
	interval := cfg.IntervalNormal

	switch target.Priority {
	case "critical":
		interval = cfg.IntervalCritical
	case "high":
		interval = cfg.IntervalHigh
	}

	log.Printf(
		"Collector started - target=%s ip=%s priority=%s interval=%s",
		target.Name, target.IP, target.Priority, interval,
	)

	// Run immediately on first start then on interval
	collectFromTarget(target, cfg, sem)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-shutdown:
			log.Printf("Collector stopped - target=%s", target.Name)
			return
		case <-ticker.C:
			collectFromTarget(target, cfg, sem)
		}
	}
}

func collectFromTarget(
	target Target,
	cfg HarvesterConfig,
	sem chan struct{},
) {
	// Acquire semaphore slot
	sem <- struct{}{}
	defer func() { <-sem }()

	client, err := newWinRMClient(target, cfg)
	if err != nil {
		log.Printf(
			"WinRM connection failed - target=%s ip=%s error=%v",
			target.Name, target.IP, err,
		)
		return
	}

	logs := target.Logs
	if len(logs) == 0 {
		logs = []string{"Security", "System", "Application"}
	}

	for _, logName := range logs {
		events, err := collectLog(client, logName, cfg.MaxEventsPerCycle)
		if err != nil {
			log.Printf(
				"Log collection failed - target=%s log=%s error=%v",
				target.Name, logName, err,
			)
			continue
		}

		for _, event := range events {
			event["target_host"] = target.Name
			event["target_ip"] = target.IP
			event["log_name"] = logName

			output, err := json.Marshal(event)
			if err != nil {
				log.Printf("JSON marshal error - error=%v", err)
				continue
			}

			// Write to stdout - Python brain reads via subprocess pipe
			fmt.Println(string(output))
		}

		if len(events) > 0 {
			log.Printf(
				"Events collected - target=%s log=%s count=%d",
				target.Name, logName, len(events),
			)
		}
	}
}
