/*
rexdr - Active Directory Intelligence Engine
collector/winrm.go - WinRM client and AD event collection

Author  : Rayyan Umair
Date    : 2026-06-12
Purpose : Implements the WinRM connection client and Security event
          log collection scoped to AD-specific event IDs via
          PowerShell remoting.
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
	"strconv"
	"strings"

	"github.com/masterzen/winrm"
)

type WinRMClient struct {
	client *winrm.Client
	target Target
}

func newWinRMClient(target Target, cfg CollectorConfig) (*WinRMClient, error) {
	endpoint := winrm.NewEndpoint(
		target.IP, cfg.WinRMPort, cfg.UseSSL, cfg.UseSSL,
		nil, nil, nil, 0,
	)

	client, err := winrm.NewClient(endpoint, cfg.Username, cfg.Password)
	if err != nil {
		return nil, fmt.Errorf("winrm client creation failed - target=%s error=%w", target.Name, err)
	}

	return &WinRMClient{client: client, target: target}, nil
}

func collectAdEvents(client *WinRMClient, eventIDs []int, maxEvents int) ([]map[string]interface{}, error) {
	idFilter := make([]string, len(eventIDs))
	for i, id := range eventIDs {
		idFilter[i] = strconv.Itoa(id)
	}
	idFilterStr := strings.Join(idFilter, ",")

	psCommand := fmt.Sprintf(`
$ids = @(%s)
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$ids} -MaxEvents %d -ErrorAction SilentlyContinue |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    $eventData = @{}
    if ($xml.Event.EventData) {
        $xml.Event.EventData.Data | ForEach-Object {
            if ($_.Name) { $eventData[$_.Name] = $_.'#text' }
        }
    }
    @{
        id              = $_.Id.ToString() + '_' + $_.TimeCreated.ToString('yyyyMMddHHmmssfff')
        event_id        = $_.Id
        time_created    = $_.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        computer        = $_.MachineName
        username        = $eventData['TargetUserName']
        target_username = $eventData['TargetUserName']
        service_name    = $eventData['ServiceName']
        encryption_type = $eventData['TicketEncryptionType']
        message         = $_.Message
        event_data      = $eventData
    }
}
$events | ConvertTo-Json -Depth 5 -Compress
`, idFilterStr, maxEvents)

	stdout, stderr, _, err := client.client.RunWithString(winrm.Powershell(psCommand), "")
	if err != nil {
		return nil, fmt.Errorf("winrm command failed - target=%s error=%w", client.target.Name, err)
	}

	if stderr != "" {
		log.Printf("WinRM stderr - target=%s stderr=%s", client.target.Name, stderr)
	}

	stdout = strings.TrimSpace(stdout)
	if stdout == "" || stdout == "null" {
		return []map[string]interface{}{}, nil
	}

	var events []map[string]interface{}

	if strings.HasPrefix(stdout, "[") {
		if err := json.Unmarshal([]byte(stdout), &events); err != nil {
			return nil, fmt.Errorf("json parse error - target=%s error=%w", client.target.Name, err)
		}
	} else {
		var single map[string]interface{}
		if err := json.Unmarshal([]byte(stdout), &single); err != nil {
			return nil, fmt.Errorf("json parse single error - target=%s error=%w", client.target.Name, err)
		}
		events = []map[string]interface{}{single}
	}

	return events, nil
}
