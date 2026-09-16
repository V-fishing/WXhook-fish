# UIA 文本提取: 从指定 hwnd 的窗口提取所有命名元素的文本
param([long]$hwnd)
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
try {
    $e = [System.Windows.Automation.AutomationElement]::FromHandle([IntPtr]$hwnd)
    if (-not $e) { exit 1 }
    $cond = [System.Windows.Automation.Condition]::TrueCondition
    $els = $e.FindAll([System.Windows.Automation.TreeScope]::Descendants, $cond)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $count = 0
    foreach ($x in $els) {
        if ($count -ge 300) { break }
        try {
            $n = $x.Current.Name
            if ($n -and $n.Trim().Length -gt 0) {
                $t = $n.Trim()
                if (-not $seen.Contains($t)) {
                    $seen.Add($t) | Out-Null
                    Write-Output $t
                    $count++
                }
            }
        } catch { continue }
    }
} catch {
    exit 1
}
