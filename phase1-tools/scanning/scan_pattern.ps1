param(
    [int]$ProcId = 27808,
    [string]$HexPattern = "51 05 09 63",
    [int]$MaxResults = 100
)

Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public class MemScan2 {
    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(int access, bool inherit, int pid);

    [DllImport("kernel32.dll")]
    static extern bool ReadProcessMemory(IntPtr h, long addr, byte[] buf, long size, out long read);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll")]
    static extern long VirtualQueryEx(IntPtr h, long addr, out MEMORY_BASIC_INFORMATION info, int len);

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public long BaseAddress;
        public long AllocationBase;
        public int AllocationProtect;
        public int __alignment1;
        public long RegionSize;
        public int State;
        public int Protect;
        public int Type;
        public int __alignment2;
    }

    public static List<long> Scan(int pid, byte[] pattern, long maxResults) {
        var results = new List<long>();
        IntPtr h = OpenProcess(0x0410, false, pid);
        if (h == IntPtr.Zero) {
            Console.WriteLine("ERROR OpenProcess: " + Marshal.GetLastWin32Error());
            return results;
        }
        long addr = 0;
        var mbi = new MEMORY_BASIC_INFORMATION();
        long totalScanned = 0;
        byte[] buf = new byte[1 << 20];
        while (addr < 0x7FFFFFFFFFFF) {
            long r = VirtualQueryEx(h, addr, out mbi, Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
            if (r == 0) break;
            bool readable = mbi.State == 0x1000
                && (mbi.Protect & 0x100) == 0
                && mbi.Protect != 0x01 && mbi.Protect != 0x00;
            if (readable ) {
                long off = 0;
                while (off < mbi.RegionSize) {
                    long chunk = Math.Min(buf.Length, mbi.RegionSize - off);
                    long got;
                    if (ReadProcessMemory(h, mbi.BaseAddress + off, buf, chunk, out got) && got > 0) {
                        totalScanned += got;
                        for (int i = 0; i + pattern.Length <= got; i++) {
                            bool hit = true;
                            for (int j = 0; j < pattern.Length; j++) {
                                if (buf[i + j] != pattern[j]) { hit = false; break; }
                            }
                            if (hit) {
                                results.Add(mbi.BaseAddress + off + i);
                                if (results.Count >= maxResults) goto done;
                            }
                        }
                    }
                    off += chunk;
                }
            }
            addr = mbi.BaseAddress + mbi.RegionSize;
        }
    done:
        Console.WriteLine("total_scanned_bytes=" + totalScanned);
        CloseHandle(h);
        return results;
    }
}
"@

Write-Host "=== scan pattern: $HexPattern (pid $ProcId) ==="
$pattern = [byte[]]($HexPattern -split '\s+' | ForEach-Object { [Convert]::ToByte($_, 16) })
$hits = [MemScan2]::Scan($ProcId, $pattern, $MaxResults)
Write-Host ("hits: " + $hits.Count)
$hits | ForEach-Object { Write-Host ("  0x{0:X}" -f $_) }
