param([int]$ProcId = 27808)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class MemRead2 {
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll")] static extern bool ReadProcessMemory(IntPtr h, long addr, byte[] buf, long size, out long read);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    public static byte[] Read(int pid, long addr, long size) {
        IntPtr h = OpenProcess(0x0410, false, pid);
        if (h == IntPtr.Zero) return null;
        byte[] buf = new byte[size];
        long got;
        bool ok = ReadProcessMemory(h, addr, buf, size, out got);
        CloseHandle(h);
        return ok ? buf : null;
    }
}
"@

# module ranges
$mods = Get-Process -Id $ProcId -Module | ForEach-Object {
    [PSCustomObject]@{ Name = $_.ModuleName; Base = [long]$_.BaseAddress; End = [long]$_.BaseAddress + $_.ModuleMemorySize }
}

# classify each hit from before_scan.txt
$hits = Get-Content "C:\Users\fish\ZCodeProject\before_scan.txt" | Where-Object { $_ -match '^\s+0x[0-9A-F]+$' } | ForEach-Object { [Convert]::ToInt64($_.Trim(), 16) }

Write-Host ("classifying " + $hits.Count + " hits...")
foreach ($h in $hits) {
    $m = $mods | Where-Object { $h -ge $_.Base -and $h -lt $_.End } | Select-Object -First 1
    if ($m) { Write-Host ("  0x{0:X}  -> {1} (+0x{2:X})" -f $h, $m.Name, ($h - $m.Base)) }
    else { Write-Host ("  0x{0:X}  -> heap/anon" -f $h) }
}

# dump context around first two image hits (inside WeChatWin.dll)
$imgHits = @()
foreach ($h in $hits) {
    $m = $mods | Where-Object { $h -ge $_.Base -and $h -lt $_.End -and $_.Name -eq 'WeChatWin.dll' } | Select-Object -First 1
    if ($m) { $imgHits += $h }
}
Write-Host ("WeChatWin.dll image hits: " + $imgHits.Count)
foreach ($h in ($imgHits | Select-Object -First 2)) {
    $start = $h - 64
    $bytes = [MemRead2]::Read($ProcId, $start, 128)
    if ($null -eq $bytes) { Write-Host ("read failed at 0x{0:X}" -f $h); continue }
    Write-Host ("===== context around 0x{0:X} =====" -f $h)
    for ($i = 0; $i -lt $bytes.Length; $i += 16) {
        $chunk = $bytes[$i..([Math]::Min($i+15, $bytes.Length-1))]
        $hex = ($chunk | ForEach-Object { $_.ToString("X2") }) -join " "
        $ascii = ($chunk | ForEach-Object { if ($_ -ge 0x20 -and $_ -le 0x7E) { [char]$_ } else { "." } }) -join ""
        $marker = if (($i + $start) -le $h -and $h -lt ($i + $start + 16)) { " <-- version int" } else { "" }
        Write-Host ("  0x{0:X12}: {1}  {2}{3}" -f ($i + $start), $hex.PadRight(47), $ascii, $marker)
    }
}
