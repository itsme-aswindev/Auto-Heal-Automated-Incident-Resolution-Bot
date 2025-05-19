# PowerShell script to automatically resolve ServiceNow incidents

# Parameters
$serviceNowUrl = "https://url for service now.service-now.com"
$username = "Snow-service accnt Username"
$password = 'Snow-service accnt password'
$credFile = "cred.json"
$incidentFile = "Incident.txt"
$logFile = "Log.txt"
$outputDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Function to write to log and console
function Write-Log {
    param ([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    Write-Host $logMessage
    try {
        $logPath = Join-Path $outputDir $logFile
        $logMessage | Out-File -FilePath $logPath -Append -Encoding UTF8 -Force -ErrorAction Stop
    }
    catch {
        Write-Host "[$timestamp] Error writing to log file: $($_.Exception.Message)"
    }
}

# Function to update ServiceNow work notes
function Update-WorkNote {
    param ($incidentNumber, $workNote)
    try {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${username}:${password}"))
        $headers = @{
            "Authorization" = "Basic $base64AuthInfo"
            "Content-Type"  = "application/json"
            "Accept"        = "application/json"
        }
        $body = @{ "work_notes" = "[$timestamp] $workNote" } | ConvertTo-Json
        $incidentDetails = Get-IncidentDetails -incidentNumber $incidentNumber
        $sysId = $incidentDetails.sys_id
        $uri = "$serviceNowUrl/api/now/table/incident/$sysId"
        
        Invoke-RestMethod -Uri $uri -Method Patch -Headers $headers -Body $body -ErrorAction Stop
        Write-Log "Updated work note for incident $incidentNumber"
    }
    catch {
        Write-Log "Error updating work note: $($_.Exception.Message)"
    }
}

# Function to resolve incident
function Resolve-Incident {
    param ($incidentNumber)
    try {
        $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${username}:${password}"))
        $headers = @{
            "Authorization" = "Basic $base64AuthInfo"
            "Content-Type"  = "application/json"
            "Accept"        = "application/json"
        }
        $body = @{ 
            "incident_state" = "6"  # Resolved
            "close_code"     = "Resolved by Bot"
            "close_notes"    = "Issue resolved automatically by Wintel L3 Resolution Bot"
        } | ConvertTo-Json
        $incidentDetails = Get-IncidentDetails -incidentNumber $incidentNumber
        $sysId = $incidentDetails.sys_id
        $uri = "$serviceNowUrl/api/now/table/incident/$sysId"
        
        Invoke-RestMethod -Uri $uri -Method Patch -Headers $headers -Body $body -ErrorAction Stop
        Write-Log "Resolved incident $incidentNumber"
    }
    catch {
        Write-Log "Error resolving incident: $($_.Exception.Message)"
    }
}

# Function to get incident details
function Get-IncidentDetails {
    param ($incidentNumber)
    try {
        $apiUrl = "$serviceNowUrl/api/now/table/incident?sysparm_query=number=$incidentNumber&sysparm_fields=sys_id,short_description,description,configuration_item"
        $headers = @{ "Authorization" = "Basic $([Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${username}:${password}")))" }
        $response = Invoke-RestMethod -Uri $apiUrl -Headers $headers -Method Get -ErrorAction Stop
        if ($response.result.Count -gt 0) {
            return $response.result[0]
        }
        else {
            throw "No incident found with number $incidentNumber"
        }
    }
    catch {
        Write-Log "Error fetching incident details: $($_.Exception.Message)"
        return $null
    }
}

# Function to parse description
function Parse-Description {
    param ($description)
    $serverPattern = "Node\s*:\s*([A-Za-z0-9\-]+)"
    $issuePatterns = @{
        "Memory"   = "Windows_Memory_Utilization_(CRITICAL|WARNING)"
        "Service"  = "Windows_WINS_service_CRITICAL"
        "CPU"      = "Windows_CPU_Utilization_CRITICAL"
        "Drive"    = "Windows_Drive_WARNING"
        "LAN"      = "Connectivity_LAN_CRITICAL"
    }

    # Extract server name
    if ($description -match $serverPattern) {
        $serverName = $matches[1]
    }
    else {
        $serverName = $null
    }

    # Identify issue type
    $issueType = $null
    foreach ($issue in $issuePatterns.Keys) {
        if ($description -match $issuePatterns[$issue]) {
            $issueType = $issue
            if ($issue -eq "Drive") {
                $driveLetter = $description -replace ".*WARNING:\s*([A-Za-z]:).*", '$1'
            }
            elseif ($issue -eq "Service") {
                $serviceMatch = $description -match "CRITICAL:\s*(.+?)\s*stopped"
                $services = if ($serviceMatch) { $matches[1] -split ",\s*" } else { @() }
            }
            break
        }
    }

    # Debugging: Log if parsing fails
    if (-not $serverName -or -not $issueType) {
        Write-Log "Failed to parse description: '$description'"
    }

    return [PSCustomObject]@{
        ServerName  = $serverName
        IssueType   = $issueType
        DriveLetter = if ($issueType -eq "Drive") { $driveLetter } else { $null }
        Services    = if ($issueType -eq "Service") { $services } else { @() }
    }
}

# Main script
while ($true) {
    Write-Log "Script execution started"
    
    # Load credentials from JSON
    $credPath = Join-Path $outputDir $credFile
    try {
        $cred = Get-Content $credPath | ConvertFrom-Json
        $ciCred = New-Object PSCredential ($cred.username, (ConvertTo-SecureString $cred.password -AsPlainText -Force))
    }
    catch {
        Write-Log "Error loading credentials from $credFile : $($_.Exception.Message)"
        Start-Sleep -Seconds 600
        continue
    }

    # Read incidents
    $incidents = Get-Content (Join-Path $outputDir $incidentFile) -ErrorAction SilentlyContinue
    
    if ($incidents) {
        foreach ($incident in $incidents) {
            Write-Log "Processing incident: $incident"
            Update-WorkNote -incidentNumber $incident -workNote "Wintel L3 Resolution Bot - Execution Started."

            # Get incident details
            $incidentDetails = Get-IncidentDetails -incidentNumber $incident
            if (-not $incidentDetails) {
                Update-WorkNote -incidentNumber $incident -workNote "Failed to retrieve incident details - manual intervention required"
                continue
            }
            $description = $incidentDetails.description
            $parsedInfo = Parse-Description -description $description
            $serverName = $parsedInfo.ServerName
            $issueType = $parsedInfo.IssueType

            if (-not $serverName -or -not $issueType) {
                Write-Log "Unable to parse server name or issue type for incident $incident"
                Update-WorkNote -incidentNumber $incident -workNote "Unable to identify server or issue type - manual intervention required"
                continue
            }

            Update-WorkNote -incidentNumber $incident -workNote "Checking the CI - $serverName"
            Update-WorkNote -incidentNumber $incident -workNote "Identifying the Issue on - $serverName"
            Update-WorkNote -incidentNumber $incident -workNote "Issue identified - $issueType"

            # Establish session to CI
            try {
                $session = New-PSSession -ComputerName $serverName -Credential $ciCred -Authentication Negotiate -ErrorAction Stop
            }
            catch {
                Write-Log "Failed to connect to $serverName : $($_.Exception.Message)"
                Update-WorkNote -incidentNumber $incident -workNote "Failed to connect to $serverName - manual intervention required: $($_.Exception.Message)"
                Update-WorkNote -incidentNumber $incident -workNote "Wintel L3 Resolution Bot - Execution Stopped."
                continue
            }

            # Ping the server within the session
            try {
                $pingResult = Invoke-Command -Session $session -ScriptBlock { Test-Connection -ComputerName $env:COMPUTERNAME -Count 4 -ErrorAction Stop }
                Update-WorkNote -incidentNumber $incident -workNote "Server $serverName is reachable"
            }
            catch {
                Write-Log "Failed to ping $serverName : $($_.Exception.Message)"
                Update-WorkNote -incidentNumber $incident -workNote "Server $serverName is unreachable: $($_.Exception.Message)"
                Update-WorkNote -incidentNumber $incident -workNote "Wintel L3 Resolution Bot - Execution Stopped."
                Remove-PSSession $session
                continue
            }

            Update-WorkNote -incidentNumber $incident -workNote "Verifying this issue on the CI $serverName"

            switch ($issueType) {
                "LAN" {
                    $uptime = Invoke-Command -Session $session -ScriptBlock { (Get-Date) - (Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue).LastBootUpTime }
                    Update-WorkNote -incidentNumber $incident -workNote "Issue is resolved on the CI $serverName - Server is pinging. Uptime: $uptime`nScript used: Test-Connection -ComputerName $env:COMPUTERNAME -Count 4"
                    Resolve-Incident -incidentNumber $incident
                }
                "Memory" {
                    try {
                        $mem = Invoke-Command -Session $session -ScriptBlock { 
                            $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
                            $memUsage = $os.TotalVisibleMemorySize - $os.FreePhysicalMemory
                            $totalMem = $os.TotalVisibleMemorySize
                            if ($totalMem -eq 0) { throw "Total memory is zero" }
                            $percent = [math]::Round(($memUsage / $totalMem) * 100, 2)
                            $topProcesses = Get-Process -ErrorAction Stop | Sort-Object WS -Descending | Select-Object -First 3 Name, @{Name = "Memory(MB)"; Expression = { [math]::Round($_.WS / 1MB, 2) } }
                            [PSCustomObject]@{ Percent = $percent; TopProcesses = $topProcesses }
                        }
                        if ($mem.Percent -ge 80) {
                            $note = "Issue persists on the CI $serverName - Memory utilization: $($mem.Percent)%`nTop 3 memory consuming processes:`n$($mem.TopProcesses | Format-Table -AutoSize | Out-String)`nScript used: Get-Process | Sort WS -Descending | Select -First 3"
                            Update-WorkNote -incidentNumber $incident -workNote $note
                        }
                        else {
                            Update-WorkNote -incidentNumber $incident -workNote "Issue is resolved on the CI $serverName - Memory utilization under control: $($mem.Percent)%`nScript used: Get-WmiObject -Class Win32_OperatingSystem"
                            Resolve-Incident -incidentNumber $incident
                        }
                    }
                    catch {
                        Write-Log "Error checking memory on $serverName : $($_.Exception.Message)"
                        Update-WorkNote -incidentNumber $incident -workNote "Error checking memory utilization on $serverName : $($_.Exception.Message)"
                    }
                }
                "CPU" {
                    try {
                        $cpu = Invoke-Command -Session $session -ScriptBlock { 
                            $cpuUsage = (Get-WmiObject -Class Win32_Processor -ErrorAction Stop).LoadPercentage
                            $topProcesses = Get-Process -ErrorAction Stop | Sort-Object CPU -Descending | Select-Object -First 3 Name, @{Name = "CPU(%)"; Expression = { [math]::Round($_.CPU, 2) } }
                            [PSCustomObject]@{ Usage = $cpuUsage; TopProcesses = $topProcesses }
                        }
                        if ($cpu.Usage -ge 80) {
                            $note = "Issue persists on the CI $serverName - CPU utilization: $($cpu.Usage)%`nTop 3 CPU consuming processes:`n$($cpu.TopProcesses | Format-Table -AutoSize | Out-String)`nScript used: Get-Process | Sort CPU -Descending | Select -First 3"
                            Update-WorkNote -incidentNumber $incident -workNote $note
                        }
                        else {
                            Update-WorkNote -incidentNumber $incident -workNote "Issue is resolved on the CI $serverName - CPU utilization under control: $($cpu.Usage)%`nScript used: Get-WmiObject -Class Win32_Processor"
                            Resolve-Incident -incidentNumber $incident
                        }
                    }
                    catch {
                        Write-Log "Error checking CPU on $serverName : $($_.Exception.Message)"
                        Update-WorkNote -incidentNumber $incident -workNote "Error checking CPU utilization on $serverName : $($_.Exception.Message)"
                    }
                }
                "Drive" {
                    $driveLetter = $parsedInfo.DriveLetter.TrimEnd(":")
                    try {
                        $drive = Invoke-Command -Session $session -ScriptBlock { 
                            Get-PSDrive -Name $using:driveLetter -PSProvider FileSystem -ErrorAction Stop | Select-Object Used, Free, @{Name = "FreePercent"; Expression = { [math]::Round(($_.Free / ($_.Used + $_.Free)) * 100, 2) } }
                        }
                        if ($drive.FreePercent -gt 15) {
                            Update-WorkNote -incidentNumber $incident -workNote "Issue is resolved on the CI $serverName - Drive space is above threshold (15%): $($drive.FreePercent)% free`nScript used: Get-PSDrive -Name $driveLetter"
                            Resolve-Incident -incidentNumber $incident
                        }
                        else {
                            Update-WorkNote -incidentNumber $incident -workNote "Issue persists on the CI $serverName - Drive space below threshold: $($drive.FreePercent)% free`nScript used: Get-PSDrive -Name $driveLetter"
                        }
                    }
                    catch {
                        Write-Log "Error checking drive on $serverName : $($_.Exception.Message)"
                        Update-WorkNote -incidentNumber $incident -workNote "Error checking drive space on $serverName : $($_.Exception.Message)"
                    }
                }
                "Service" {
                    foreach ($serviceName in $parsedInfo.Services) {
                        try {
                            $service = Invoke-Command -Session $session -ScriptBlock {
                                $svc = Get-Service -Name $using:serviceName -ErrorAction Stop
                                if ($svc.Status -ne "Running") {
                                    Start-Service -Name $using:serviceName -ErrorAction Stop
                                    $newStatus = (Get-Service -Name $using:serviceName).Status
                                    return [PSCustomObject]@{ Exists = $true; Status = $newStatus; Name = $using:serviceName }
                                }
                                return [PSCustomObject]@{ Exists = $true; Status = $svc.Status; Name = $using:serviceName }
                            }
                            if ($service.Status -eq "Running") {
                                Update-WorkNote -incidentNumber $incident -workNote "Issue is resolved on the CI $serverName - Service $($service.Name) is running`nScript used: Get-Service -Name $($service.Name)"
                                Resolve-Incident -incidentNumber $incident
                            }
                            else {
                                Update-WorkNote -incidentNumber $incident -workNote "Issue persists on the CI $serverName - Unable to start service $($service.Name)`nScript used: Start-Service -Name $($service.Name)"
                            }
                        }
                        catch {
                            Write-Log "Error checking service $serviceName on $serverName : $($_.Exception.Message)"
                            Update-WorkNote -incidentNumber $incident -workNote "Error handling service $($serviceName) on $serverName : $($_.Exception.Message)"
                        }
                    }
                }
            }

            Update-WorkNote -incidentNumber $incident -workNote "Wintel L3 Resolution Bot - Execution Stopped."
            Remove-PSSession $session
        }
    }
    else {
        Write-Log "No incidents found in Incident.txt"
    }

    Write-Log "Script execution completed - waiting 10 minutes"
    Start-Sleep -Seconds 600  # 10 minutes
}