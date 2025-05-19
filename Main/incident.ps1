# PowerShell script to fetch ServiceNow incidents with Basic Authentication

# Parameters (modify these as needed)
$serviceNowUrl = "https://url for service now.service-now.com"
$apiUrl = "$serviceNowUrl/api/now/table/incident?sysparm_query=active=true^assigned_to=f6e4ce1697fbe154aec1b67de053af63^incident_stateBETWEEN1@3&sysparm_fields=number&sysparm_limit=1000"
$username = "Snow-service accnt Username"  # Replace with actual username
$password = 'Snow-service accnt password'  # Example password with $, using single quotes
$outputFile = "Incident.txt"

try {
    # Create Basic Authentication header
    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("${username}:${password}")))
    $headers = @{
        "Authorization" = "Basic $base64AuthInfo"
        "Accept" = "application/json"
    }

    # Make the REST API call
    $response = Invoke-RestMethod -Uri $apiUrl `
                                 -Method Get `
                                 -Headers $headers `
                                 -ContentType "application/json" `
                                 -ErrorAction Stop

    # Extract incident numbers from the response
    $incidentNumbers = $response.result | Select-Object -ExpandProperty number

    if ($incidentNumbers) {
        # Get the script's current directory
        $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
        $outputPath = Join-Path -Path $scriptPath -ChildPath $outputFile

        # Write incident numbers to text file
        $incidentNumbers | Out-File -FilePath $outputPath -Encoding UTF8
        
        Write-Host "Successfully retrieved $($incidentNumbers.Count) incidents and saved to $outputPath"
        Write-Host "Incidents found:"
        $incidentNumbers | ForEach-Object { Write-Host $_ }
    }
    else {
        Write-Host "No incidents found matching the criteria."
    }
}
catch {
    # Error handling
    Write-Error "An error occurred: $($_.Exception.Message)"
    Write-Error "Stack trace: $($_.ScriptStackTrace)"
    
    # Additional error details
    if ($_.Exception.Response) {
        $errorResponse = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $errorDetails = $reader.ReadToEnd()
        Write-Error "Response details: $errorDetails"
    }
}