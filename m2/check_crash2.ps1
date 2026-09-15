# 最近 3 条 Weixin 崩溃的完整签名
$events = Get-WinEvent -FilterHashtable @{LogName='Application'; Id=1000; StartTime=(Get-Date).AddHours(-2)} -MaxEvents 3 -ErrorAction SilentlyContinue
foreach ($e in $events) {
    Write-Host ('===' + $e.TimeCreated)
    $m = $e.Message
    if ($m.Length -gt 350) { $m = $m.Substring(0, 350) }
    Write-Host $m
    Write-Host ''
}
