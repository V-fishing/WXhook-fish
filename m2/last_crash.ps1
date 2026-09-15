$e = Get-WinEvent -FilterHashtable @{LogName='Application'; Id=1000} -MaxEvents 1 -ErrorAction SilentlyContinue
Write-Host $e.TimeCreated
$m = $e.Message
if ($m.Length -gt 300) { $m = $m.Substring(0, 300) }
Write-Host $m
