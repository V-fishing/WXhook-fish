param(
    [int]$ProcId = 27808,
    [long]$Address = 0x1CDF2B47E30,
    [string]$NewVersion = "4.1.13.65"
)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class MemWrite {
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll")] static extern bool WriteProcessMemory(IntPtr h, long addr, byte[] buf, long size, out long written);
    [DllImport("kernel32.dll")] static extern bool ReadProcessMemory(IntPtr h, long addr, byte[] buf, long size, out long read);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);

    public static bool Write(int pid, long addr, byte[] data) {
        IntPtr h = OpenProcess(0x0438, false, pid); // QUERY | VM_READ | VM_WRITE | VM_OPERATION
        if (h == IntPtr.Zero) { Console.WriteLine("OpenProcess failed: " + Marshal.GetLastWin32Error()); return false; }
        long written;
        bool ok = WriteProcessMemory(h, addr, data, data.Length, out written);
        CloseHandle(h);
        Console.WriteLine("written=" + written + " ok=" + ok);
        return ok;
    }

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

# show before
$before = [MemWrite]::Read($ProcId, $Address, 40)
if ($null -eq $before) { Write-Host "read failed"; exit 1 }
$beforeStr = [System.Text.Encoding]::Unicode.GetString($before).Split([char]0)[0]
Write-Host ("before: '" + $beforeStr + "'")

# build new bytes: UTF-16LE string + null terminator
$newBytes = [System.Text.Encoding]::Unicode.GetBytes($NewVersion)
$payload = New-Object byte[] ($newBytes.Length + 2)
[Array]::Copy($newBytes, $payload, $newBytes.Length)  # trailing nulls already zero

if ($payload.Length -gt 40) { Write-Host "string too long!"; exit 1 }
Write-Host ("writing " + $payload.Length + " bytes (UTF-16 '" + $NewVersion + "') to 0x" + $Address.ToString("X"))
$ok = [MemWrite]::Write($ProcId, $Address, $payload)

# show after
$after = [MemWrite]::Read($ProcId, $Address, 40)
$afterStr = [System.Text.Encoding]::Unicode.GetString($after).Split([char]0)[0]
Write-Host ("after:  '" + $afterStr + "'")
if ($ok -and $afterStr -eq $NewVersion) { Write-Host "PATCH OK" } else { Write-Host "PATCH FAILED" }
