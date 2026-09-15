param([int]$ProcId = 27808)

Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public class MemScan {
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

    // scan all committed readable regions for a byte pattern
    public static List<long> Scan(int pid, byte[] pattern, long maxResults) {
        var results = new List<long>();
        IntPtr h = OpenProcess(0x0410, false, pid); // QUERY_INFORMATION | VM_READ
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
            bool readable = mbi.State == 0x1000 // MEM_COMMIT
                && (mbi.Protect & 0x100) == 0   // not PAGE_GUARD
                && mbi.Protect != 0x01 && mbi.Protect != 0x00; // not NOACCESS/INVALID
            if (readable && mbi.RegionSize <= (64L << 20)) {
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

# --- 1) 4-byte int 0x03090551 (3.9.5.81 packed) ---
$intPattern = [byte[]](0x51,0x05,0x09,0x03)
Write-Host "=== scan 4-byte int 03090551 (3.9.5.81) ==="
$hits = [MemScan]::Scan($ProcId, $intPattern, 100)
Write-Host ("int hits: " + $hits.Count)
$hits | ForEach-Object { Write-Host ("  0x{0:X}" -f $_) }

# --- 2) UTF-16LE string "3.9.5.81" ---
$s = "3.9.5.81"
$u16 = [System.Text.Encoding]::Unicode.GetBytes($s)
Write-Host "=== scan UTF-16 string '3.9.5.81' ==="
$hits2 = [MemScan]::Scan($ProcId, $u16, 20)
Write-Host ("utf16 hits: " + $hits2.Count)
$hits2 | ForEach-Object { Write-Host ("  0x{0:X}" -f $_) }
