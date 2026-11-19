
param(
    [string]$EventName = "ListUsers",
    [int]$LookbackHours = 24
)

$ErrorActionPreference = "Stop"

$StartTime = (Get-Date).ToUniversalTime().AddHours(-$LookbackHours)
$EndTime = (Get-Date).ToUniversalTime()

Write-Host "Recherche CloudTrail : $EventName"
Write-Host "Période UTC : $StartTime -> $EndTime"

$Events = aws cloudtrail lookup-events `
    --lookup-attributes "AttributeKey=EventName,AttributeValue=$EventName" `
    --start-time $StartTime.ToString("yyyy-MM-ddTHH:mm:ssZ") `
    --end-time $EndTime.ToString("yyyy-MM-ddTHH:mm:ssZ") `
    --region us-east-1 `
    --profile cloud-admin `
    --output json | ConvertFrom-Json

if ($LASTEXITCODE -ne 0) {
    throw "La recherche CloudTrail a échoué."
}

$Events.Events |
Select-Object EventTime, EventName, Username, EventId |
Format-Table -AutoSize
