/*
rexdr - Windows Event Intelligence Engine
harvester/winrm.go - WinRM client and event collection

Author  : Rayyan Umair
Date    : 2026-06-12
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

func collectLog(
	client *WinRMClient,
	logName string,
	maxEvents int,
) ([]map[string]interface{}, error) {

	// PowerShell command to collect events and serialize to JSON
	// Gets the last maxEvents events from the specified log
	// Returns a JSON array of event objects
	psCommand := fmt.Sprintf(`
$events = Get-WinEvent -LogName '%s' -MaxEvents %d -ErrorAction SilentlyContinue |
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
`, logName, maxEvents)

	stdout, stderr, _, err := client.client.RunWithString(
		winrm.Powershell(psCommand), "",
	)

	if err != nil {
		return nil, fmt.Errorf(
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
		return []map[string]interface{}{}, nil
	}

	// The PowerShell output may be a single object or an array
	// Normalize to always be an array
	var events []map[string]interface{}

	if strings.HasPrefix(stdout, "[") {
		if err := json.Unmarshal([]byte(stdout), &events); err != nil {
			return nil, fmt.Errorf(
				"json parse error - target=%s log=%s error=%w",
				client.target.Name, logName, err,
			)
		}
	} else {
		// Single event object
		var single map[string]interface{}
		if err := json.Unmarshal([]byte(stdout), &single); err != nil {
			return nil, fmt.Errorf(
				"json parse single error - target=%s log=%s error=%w",
				client.target.Name, logName, err,
			)
		}
		events = []map[string]interface{}{single}
	}

	return events, nil
}
