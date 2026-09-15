# 查 Weixin 崩溃记录
$events = Get-WinEvent -FilterHashtable @{LogName='Application'; Id=1000,1001,1002; StartTime=(Get-Date).AddMinutes(-20)} -MaxEvents 5 -ErrorAction SilentlyContinue
foreach ($e in $events) {
    Write-Host ('--- ' + $e.TimeCreated + ' Id=' + $e.Id)
    $m = $e.Message
    if ($m.Length -gt 600) { $m = $m.Substring(0, 600) }
    Write-Host $m
    Write-Host ''
}
if (-not $events) { Write-Host 'NO crash events found in last 20 min' }
