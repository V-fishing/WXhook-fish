$e = Get-WinEvent -FilterHashtable @{LogName='Application'; Id=1000} -MaxEvents 1 -ErrorAction SilentlyContinue
$m = $e.Message -split "`r`n"
foreach ($line in $m) {
    if ($line -match '出错模块|错误偏移|异常代码|出错进程') { Write-Host $line }
}
