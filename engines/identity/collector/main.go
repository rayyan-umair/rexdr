/*
rexdr - Active Directory Intelligence Engine
collector/main.go - Go collector entry point

Author  : Rayyan Umair
Date    : 2026-06-18
Purpose : Entry point for the REXDR AD security event collector.
          Reads targets.yaml, identifies domain controller targets,
          and polls Security event logs for AD-specific event IDs.
          Multi-DC aware - deduplicates replicated events across
          multiple domain controllers using event_id and time_created
          as the dedup key. Events are written as JSON to stdout
          where the Python brain reads them via subprocess pipe.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Trust, but verify the keys."

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

// AD-specific Security event IDs to collect
var adEventIDs = []int{4768, 4769, 4771, 4670, 4704, 4705, 4719, 4624}

func main() {
	log.SetOutput(os.Stderr)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmsgprefix)
	log.SetPrefix("[REXDR-AD-COLLECTOR] ")

	log.Println("=== REXDR Active Directory Collector starting ===")

	cfg := loadConfig()

	targets, err := loadDCTargets(cfg.TargetsPath)
	if err != nil {
		log.Fatalf("Failed to load DC targets - path=%s error=%v", cfg.TargetsPath, err)
	}

	log.Printf("Domain controller targets loaded - count=%d", len(targets))

	sem := make(chan struct{}, cfg.MaxConcurrentWinRM)
	var wg sync.WaitGroup
	shutdown := make(chan struct{})

	dedup := newDedupTracker()

	for _, target := range targets {
		wg.Add(1)
		go func(t Target) {
			defer wg.Done()
			runDCCollector(t, cfg, sem, shutdown, dedup)
		}(target)
	}

	log.Printf("=== Collector running - DC targets=%d ===", len(targets))

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutdown signal received - stopping collectors")
	close(shutdown)
	wg.Wait()
	log.Println("=== REXDR Active Directory Collector stopped ===")
}

type CollectorConfig struct {
	TargetsPath         string
	Username            string
	Password            string
	WinRMPort           int
	UseSSL              bool
	MaxConcurrentWinRM  int
	MaxEventsPerCycle   int
	PollIntervalSeconds time.Duration
}

func loadConfig() CollectorConfig {
	return CollectorConfig{
		TargetsPath:         getEnv("WINRM_TARGETS_PATH", "/config/targets.yaml"),
		Username:            getEnv("WINRM_USERNAME", ""),
		Password:            getEnv("WINRM_PASSWORD", ""),
		WinRMPort:           getEnvInt("WINRM_PORT", 5985),
		UseSSL:              getEnvBool("WINRM_USE_SSL", false),
		MaxConcurrentWinRM:  getEnvInt("WINRM_MAX_CONCURRENT", 10),
		MaxEventsPerCycle:   getEnvInt("MAX_EVENTS_PER_COLLECTION", 1000),
		PollIntervalSeconds: time.Duration(getEnvInt("EVENT_POLL_INTERVAL_SECONDS", 60)) * time.Second,
	}
}

func runDCCollector(
	target Target,
	cfg CollectorConfig,
	sem chan struct{},
	shutdown chan struct{},
	dedup *DedupTracker,
) {
	log.Printf("Collector started - dc=%s ip=%s", target.Name, target.IP)

	collectFromDC(target, cfg, sem, dedup)

	ticker := time.NewTicker(cfg.PollIntervalSeconds)
	defer ticker.Stop()

	for {
		select {
		case <-shutdown:
			log.Printf("Collector stopped - dc=%s", target.Name)
			return
		case <-ticker.C:
			collectFromDC(target, cfg, sem, dedup)
		}
	}
}

func collectFromDC(
	target Target,
	cfg CollectorConfig,
	sem chan struct{},
	dedup *DedupTracker,
) {
	sem <- struct{}{}
	defer func() { <-sem }()

	client, err := newWinRMClient(target, cfg)
	if err != nil {
		log.Printf("WinRM connection failed - dc=%s error=%v", target.Name, err)
		return
	}

	events, err := collectAdEvents(client, adEventIDs, cfg.MaxEventsPerCycle)
	if err != nil {
		log.Printf("Event collection failed - dc=%s error=%v", target.Name, err)
		return
	}

	uniqueCount := 0
	for _, event := range events {
		dedupKey := fmt.Sprintf("%v_%v", event["event_id"], event["time_created"])
		if dedup.isDuplicate(dedupKey) {
			continue
		}

		event["target_host"] = target.Name
		event["target_ip"] = target.IP

		output, err := json.Marshal(event)
		if err != nil {
			log.Printf("JSON marshal error - error=%v", err)
			continue
		}

		fmt.Println(string(output))
		uniqueCount++
	}

	if uniqueCount > 0 {
		log.Printf("Events collected - dc=%s unique=%d total=%d", target.Name, uniqueCount, len(events))
	}
}
