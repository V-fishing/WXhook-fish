param(
    [int]$ProcId = 27808,
    [long[]]$Addresses = @(0x1CDF25FD84C, 0x1CDF26127AA, 0x1CDF46485FA, 0x2B7E6FF31A)
)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class MemDump {
    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(int access, bool inherit, int pid);

    [DllImport("kernel32.dll")]
    static extern bool ReadProcessMemory(IntPtr h, long addr, byte[] buf, long size, out long read);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr h);

    public static byte[] Read(int pid, long addr, long size) {
        IntPtr h = OpenProcess(0x0410, false, pid);
        if (h == IntPtr.Zero) return null;
        byte[] buf = new byte[size];
        long got;
        bool ok = ReadProcessMemory(h, addr, buf, size, out got);
        CloseHandle(h);
        if (!ok) return null;
        if (got < size) { Array.Resize(ref buf, (int)got); }
        return buf;
    }
}
"@

foreach ($addr in $Addresses) {
    $start = $addr - 48
    $bytes = [MemDump]::Read($ProcId, $start, 144)
    if ($null -eq $bytes) { Write-Host ("0x{0:X}: READ FAILED" -f $addr); continue }
    Write-Host ("===== around 0x{0:X} =====" -f $addr)
    for ($i = 0; $i -lt $bytes.Length; $i += 16) {
        $chunk = $bytes[$i..([Math]::Min($i+15, $bytes.Length-1))]
        $hex = ($chunk | ForEach-Object { $_.ToString("X2") }) -join " "
        $ascii = ($chunk | ForEach-Object { if ($_ -ge 0x20 -and $_ -le 0x7E) { [char]$_ } else { "." } }) -join ""
        $marker = ""
        $off = $i + $start
        if ($addr -ge $off -and $addr -lt ($off + 16)) { $marker = " <-- version string" }
        Write-Host ("  0x{0:X12}: {1}  {2}{3}" -f $off, $hex.PadRight(47), $ascii, $marker)
    }
}
