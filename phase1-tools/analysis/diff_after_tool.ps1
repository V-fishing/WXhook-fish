param([int]$ProcId = 27808)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class MemRead3 {
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

$mods = Get-Process -Id $ProcId -Module | ForEach-Object {
    [PSCustomObject]@{ Name = $_.ModuleName; Base = [long]$_.BaseAddress; End = [long]$_.BaseAddress + $_.ModuleMemorySize }
}

$hits = Get-Content "C:\Users\fish\ZCodeProject\before_scan.txt" | Where-Object { $_ -match '^\s+0x[0-9A-F]+$' } | ForEach-Object { [Convert]::ToInt64($_.Trim(), 16) }

Write-Host ("reading " + $hits.Count + " recorded addresses (before: 0x63090551)...")
foreach ($h in $hits) {
    $bytes = [MemRead3]::Read($ProcId, $h, 4)
    if ($null -eq $bytes) { Write-Host ("  0x{0,X16}  READ FAILED" -f $h); continue }
    $val = [BitConverter]::ToUInt32($bytes, 0)
    $m = $mods | Where-Object { $h -ge $_.Base -and $h -lt $_.End } | Select-Object -First 1
    $where = if ($m) { ("{1}+0x{2:X}" -f 0, $m.Name, ($h - $m.Base)) } else { "heap" }
    $changed = if ($val -ne 0x63090551) { " <<< CHANGED" } else { "" }
    Write-Host ("  0x{0:X16}  {1}  now=0x{2:X8}{3}" -f $h, $where.PadRight(24), $val, $changed)
}
