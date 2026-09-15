param(
    [int]$ProcId = 11180,
    [string]$OldPattern = "51 05 09 63",   # 0x63090551 = 3.9.5.81
    [string]$NewPattern = "11 0B 09 63",   # 0x63090B11 = 3.9.11.17
    [switch]$Apply
)

Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public class IntPatch {
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadProcessMemory(IntPtr h, long addr, byte[] buf, long size, out long read);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool WriteProcessMemory(IntPtr h, long addr, byte[] buf, long size, out long written);
    [DllImport("kernel32.dll", SetLastError=true)] static extern long VirtualQueryEx(IntPtr h, long addr, out MEMORY_BASIC_INFORMATION info, int len);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public long BaseAddress; public long AllocationBase; public int AllocationProtect; public int __a1;
        public long RegionSize; public int State; public int Protect; public int Type; public int __a2;
    }

    // find all occurrences in WRITABLE committed regions, optionally patch them
    public static string Run(int pid, byte[] oldPat, byte[] newPat, bool apply) {
        IntPtr h = OpenProcess(apply ? 0x0438 : 0x0410, false, pid);
        if (h == IntPtr.Zero) return "OpenProcess failed err=" + Marshal.GetLastWin32Error();
        var hits = new List<long>();
        long addr = 0;
        var mbi = new MEMORY_BASIC_INFORMATION();
        byte[] buf = new byte[1 << 20];
        while (addr < 0x7FFFFFFFFFFF) {
            long q = VirtualQueryEx(h, addr, out mbi, Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
            if (q == 0) break;
            bool ok = mbi.State == 0x1000 && (mbi.Protect & 0x100) == 0 && mbi.Protect != 0x01 && mbi.Protect != 0x00;
            // writable check: PAGE_READWRITE(0x04) | WRITECOPY(0x08) | EXECUTE_READWRITE(0x40) | EXECUTE_WRITECOPY(0x80), also 0x02|... no
            int p = mbi.Protect;
            bool writable = (p & (0x04 | 0x08 | 0x40 | 0x80)) != 0 || p == 0x04;
            if (ok && writable && mbi.RegionSize <= (256L << 20)) {
                long off = 0;
                while (off < mbi.RegionSize) {
                    long chunk = Math.Min(buf.Length, mbi.RegionSize - off);
                    long got;
                    if (ReadProcessMemory(h, mbi.BaseAddress + off, buf, chunk, out got) && got >= oldPat.Length) {
                        for (int i = 0; i + oldPat.Length <= got; i++) {
                            bool hit = true;
                            for (int j = 0; j < oldPat.Length; j++) { if (buf[i + j] != oldPat[j]) { hit = false; break; } }
                            if (hit) hits.Add(mbi.BaseAddress + off + i);
                        }
                    }
                    off += chunk;
                }
            }
            addr = mbi.BaseAddress + mbi.RegionSize;
        }
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("writable-region hits: " + hits.Count);
        int patched = 0, failed = 0;
        foreach (long a in hits) {
            if (apply) {
                long w;
                if (WriteProcessMemory(h, a, newPat, newPat.Length, out w)) patched++;
                else failed++;
            }
        }
        if (apply) sb.AppendLine("patched=" + patched + " failed=" + failed);
        // verify a few
        foreach (long a in hits) {
            byte[] b = new byte[4]; long got;
            if (ReadProcessMemory(h, a, b, 4, out got))
                sb.AppendLine(string.Format("  0x{0:X16} -> 0x{1:X8}", a, BitConverter.ToUInt32(b, 0)));
        }
        CloseHandle(h);
        return sb.ToString();
    }
}
"@

function ParseHex([string]$hex) {
    $parts = $hex -split '\s+'
    $bytes = New-Object byte[] $parts.Length
    for ($i = 0; $i -lt $parts.Length; $i++) { $bytes[$i] = [Convert]::ToByte($parts[$i], 16) }
    return $bytes
}

$old = ParseHex $OldPattern
$new = ParseHex $NewPattern
if ($old.Length -ne $new.Length) { Write-Host "pattern length mismatch"; exit 1 }

Write-Host ("running on pid " + $ProcId + " apply=" + $Apply.IsPresent)
Write-Host ([IntPatch]::Run($ProcId, $old, $new, $Apply.IsPresent))
