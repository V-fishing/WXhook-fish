param([int]$ProcId = 31396)

Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

$cond = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::ProcessIdProperty, $ProcId)
$root = [System.Windows.Automation.AutomationElement]::RootElement
$win = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $cond)
if ($null -eq $win) {
    Write-Host "window not found for pid $ProcId"
    exit 1
}
Write-Host ("window: '" + $win.Current.Name + "' class=" + $win.Current.ClassName + " rect=" + $win.Current.BoundingRectangle)

function Walk([System.Windows.Automation.AutomationElement]$el, [int]$depth) {
    if ($depth -gt 12) { return }
    $walker = [System.Windows.Automation.TreeWalker]::ControlViewWalker
    $child = $walker.GetFirstChild($el)
    while ($null -ne $child) {
        $name = $child.Current.Name
        $type = $child.Current.ControlType.ProgrammaticName
        $off = $child.Current.IsOffscreen
        if ($name -and $name.Trim().Length -gt 0) {
            Write-Host ("  " * $depth + "[" + $type + "] offscreen=" + $off + " '" + $name + "'")
        } elseif ($type -match "Text|Button|Edit") {
            Write-Host ("  " * $depth + "[" + $type + "] offscreen=" + $off + " (empty)")
        }
        Walk $child ($depth + 1)
        $child = $walker.GetNextSibling($child)
    }
}
Walk $win 0
