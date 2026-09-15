param(
    [int]$ProcId = 31396,
    [long[]]$Addresses = @(0x27C8013446E, 0x27C80772E20, 0x27C81E134A0),
    [int]$Length = 800
)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class U16 {
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(int a, bool i, int p);
    [DllImport("kernel32.dll")] static extern bool ReadProcessMemory(IntPtr h, long a, byte[] b, long s, out long r);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    public static byte[] Go(int pid, long addr, int len) {
        IntPtr h = OpenProcess(0x0410, false, pid);
        if (h == IntPtr.Zero) return null;
        byte[] b = new byte[len];
        long got;
        bool ok = ReadProcessMemory(h, addr, b, len, out got);
        CloseHandle(h);
        return ok ? b : null;
    }
}
"@

foreach ($addr in $Addresses) {
    Write-Host ("===== @0x" + $addr.ToString("X") + " =====")
    $bytes = [U16]::Go($ProcId, $addr, $Length)
    if ($null -eq $bytes) { Write-Host "read failed"; continue }
    $text = [System.Text.Encoding]::Unicode.GetString($bytes)
    # clean: keep printable, replace nulls with newline markers
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $text.ToCharArray()) {
        if ($ch -eq [char]0) { $sb.Append([char]0x2400) }  # visible marker for null
        elseif ([int]$ch -lt 32) { $sb.Append('.') }
        else { $sb.Append($ch) }
    }
    Write-Host $sb.ToString()
    Write-Host ""
}
