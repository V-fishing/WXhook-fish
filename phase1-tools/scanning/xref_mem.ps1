param(
    [int]$ProcId = 9936,
    [long]$StringVa = 0x21815D87840,
    [int]$MaxHits = 30
)

Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public class XRef {
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadProcessMemory(IntPtr h, long addr, byte[] buf, long size, out long read);
    [DllImport("kernel32.dll", SetLastError=true)] static extern long VirtualQueryEx(IntPtr h, long addr, out MEMORY_BASIC_INFORMATION info, int len);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public long BaseAddress; public long AllocationBase; public int AllocationProtect; public int __a1;
        public long RegionSize; public int State; public int Protect; public int Type; public int __a2;
    }

    // scan readable memory for a dword D at address i where (i+4)+D == targetVa
    public static List<long> Scan(int pid, long targetVa) {
        var hits = new List<long>();
        IntPtr h = OpenProcess(0x0410, false, pid);
        if (h == IntPtr.Zero) { Console.WriteLine("OpenProcess failed"); return hits; }
        long addr = 0;
        var mbi = new MEMORY_BASIC_INFORMATION();
        byte[] buf = new byte[1 << 20];
        while (addr < 0x7FFFFFFFFFFF) {
            long q = VirtualQueryEx(h, addr, out mbi, Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
            if (q == 0) break;
            bool readable = mbi.State == 0x1000 && (mbi.Protect & 0x100) == 0 && mbi.Protect != 0x01 && mbi.Protect != 0x00;
            if (readable && mbi.RegionSize <= (64L << 20)) {
                long off = 0;
                while (off < mbi.RegionSize) {
                    long chunk = Math.Min(buf.Length, mbi.RegionSize - off);
                    long got;
                    if (ReadProcessMemory(h, mbi.BaseAddress + off, buf, chunk, out got) && got >= 4) {
                        for (int i = 0; i + 4 <= got; i += 1) {
                            int d = BitConverter.ToInt32(buf, i);
                            long insnEnd = mbi.BaseAddress + off + i + 4;
                            if (insnEnd + d == targetVa) {
                                hits.Add(mbi.BaseAddress + off + i);
                            }
                        }
                    }
                    off += chunk;
                }
            }
            addr = mbi.BaseAddress + mbi.RegionSize;
        }
        CloseHandle(h);
        return hits;
    }

    public static byte[] ReadAt(int pid, long addr, int len) {
        IntPtr h = OpenProcess(0x0410, false, pid);
        if (h == IntPtr.Zero) return null;
        byte[] b = new byte[len]; long got;
        bool ok = ReadProcessMemory(h, addr, b, len, out got);
        CloseHandle(h);
        return ok ? b : null;
    }
}
"@

Write-Host ("scanning pid " + $ProcId + " for xrefs to 0x" + $StringVa.ToString("X"))
$hits = [XRef]::Scan($ProcId, $StringVa)
Write-Host ("hits: " + $hits.Count)
foreach ($h in $hits) {
    if ($hits.IndexOf($h) -ge $MaxHits) { break }
    Write-Host ("  xref disp @ 0x{0:X}" -f $h)
    $bytes = [XRef]::ReadAt($ProcId, $h - 8, 32)
    if ($bytes) {
        $hex = ($bytes | ForEach-Object { $_.ToString("X2") }) -join " "
        Write-Host ("     ctx: " + $hex)
    }
}
