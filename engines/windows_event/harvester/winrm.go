/*
rexdr - Windows Event Intelligence Engine
harvester/winrm.go - WinRM client and event collection

Author  : Rayyan Umair
Date    : 2026-06-12
Updated : 2026-07-10 - collectLog now accepts and returns a checkpoint
          (`since`), so each target+log pair only fetches events newer
          than the last one already collected instead of always
          re-fetching the same most-recent-N-events window. Without
          this, the harvester looped forever re-processing the same
          batch of events on every cycle, causing sustained high CPU
          and never actually advancing through new activity.
Purpose : Implements the WinRM connection client and Windows Event
          Log collection via PowerShell remoting. Queries Security,
          System, and Application event logs and returns raw event
          data as Go maps ready for JSON serialization.
          All WinRM connection logic lives here.
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
	"strings"

	"github.com/masterzen/winrm"
)

// ============================================================================
// WinRM client
// ============================================================================

type WinRMClient struct {
	client *winrm.Client
	target Target
}

func newWinRMClient(target Target, cfg HarvesterConfig) (*WinRMClient, error) {
	endpoint := winrm.NewEndpoint(
		target.IP,
		cfg.WinRMPort,
		cfg.UseSSL,
		cfg.UseSSL,
		nil,
		nil,
		nil,
		0,
	)

	client, err := winrm.NewClient(
		endpoint,
		cfg.Username,
		cfg.Password,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"winrm client creation failed - target=%s error=%w",
			target.Name, err,
		)
	}

	return &WinRMClient{
		client: client,
		target: target,
	}, nil
}

// ============================================================================
// Event collection
// ============================================================================

// collectLog fetches events for a single log on a single target. If `since`
// is empty, this is the first collection for this target+log pair and it
// fetches the most recent maxEvents as an initial backfill. On every
// subsequent call, `since` holds the time_created of the newest event
// already collected, and the query is filtered to only return events after
// that point. The function returns the updated checkpoint alongside the
// events - the caller is responsible for persisting it and passing it back
// in on the next call.
func collectLog(
	client *WinRMClient,
	logName string,
	maxEvents int,
	since string,
) ([]map[string]interface{}, string, error) {

	var getEventsLine string
	if since == "" {
		getEventsLine = fmt.Sprintf(
			`$events = Get-WinEvent -LogName '%s' -MaxEvents %d -ErrorAction SilentlyContinue |`,
			logName, maxEvents,
		)
	} else {
		getEventsLine = fmt.Sprintf(
			`$events = Get-WinEvent -FilterHashtable @{LogName='%s'; StartTime=[datetime]'%s'} -MaxEvents %d -ErrorAction SilentlyContinue |`,
			logName, since, maxEvents,
		)
	}

	psCommand := fmt.Sprintf(`
%s
ForEach-Object {
    $xml = [xml]$_.ToXml()
    $eventData = @{}
    if ($xml.Event.EventData) {
        $xml.Event.EventData.Data | ForEach-Object {
            if ($_.Name) {
                $eventData[$_.Name] = $_.'#text'
            }
        }
    }
    @{
        id            = $_.Id.ToString() + '_' + $_.TimeCreated.ToString('yyyyMMddHHmmssfff')
        event_id      = $_.Id
        log_name      = $_.LogName
        level         = $_.LevelDisplayName
        time_created  = $_.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        provider_name = $_.ProviderName
        computer      = $_.MachineName
        user_id       = if ($_.UserId) { $_.UserId.ToString() } else { $null }
        message       = $_.Message
        event_data    = $eventData
    }
}
$events | ConvertTo-Json -Depth 5 -Compress
`, getEventsLine)

	stdout, stderr, _, err := client.client.RunWithString(
		winrm.Powershell(psCommand), "",
	)

	if err != nil {
		return nil, since, fmt.Errorf(
			"winrm command failed - target=%s log=%s error=%w",
			client.target.Name, logName, err,
		)
	}

	if stderr != "" {
		log.Printf(
			"WinRM stderr - target=%s log=%s stderr=%s",
			client.target.Name, logName, stderr,
		)
	}

	stdout = strings.TrimSpace(stdout)
	if stdout == "" || stdout == "null" {
		return []map[string]interface{}{}, since, nil
	}

	// The PowerShell output may be a single object or an array
	// Normalize to always be an array
	var events []map[string]interface{}

	if strings.HasPrefix(stdout, "[") {
		if err := json.Unmarshal([]byte(stdout), &events); err != nil {
			return nil, since, fmt.Errorf(
				"json parse error - target=%s log=%s error=%w",
				client.target.Name, logName, err,
			)
		}
	} else {
		// Single event object
		var single map[string]interface{}
		if err := json.Unmarshal([]byte(stdout), &single); err != nil {
			return nil, since, fmt.Errorf(
				"json parse single error - target=%s log=%s error=%w",
				client.target.Name, logName, err,
			)
		}
		events = []map[string]interface{}{single}
	}

	// Advance the checkpoint to the newest time_created seen in this
	// batch. time_created is formatted as ISO 8601 with fixed-width,
	// zero-padded fields, so plain string comparison sorts correctly -
	// no need to parse into time.Time here.
	newCheckpoint := since
	for _, ev := range events {
		tc, ok := ev["time_created"].(string)
		if ok && tc > newCheckpoint {
			newCheckpoint = tc
		}
	}

	return events, newCheckpoint, nil
}
