param([int]$ProcId = 27808)

Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public class MaskScan {
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

    // scan for dwords where (value & mask) == matchValue, excluding excludeValue
    // returns grouped counts via a Dictionary
    public static Dictionary<uint, List<long>> ScanDwords(int pid, uint matchValue, uint mask, uint excludeValue, long maxPerValue) {
        var results = new Dictionary<uint, List<long>>();
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
            if (readable) {
                long off = 0;
                while (off < mbi.RegionSize) {
                    long chunk = Math.Min(buf.Length, mbi.RegionSize - off);
                    long got;
                    if (ReadProcessMemory(h, mbi.BaseAddress + off, buf, chunk, out got) && got >= 4) {
                        totalScanned += got;
                        for (int i = 0; i + 4 <= got; i++) {
                            uint v = BitConverter.ToUInt32(buf, i);
                            if ((v & mask) == matchValue && v != excludeValue) {
                                List<long> lst;
                                if (!results.TryGetValue(v, out lst)) { lst = new List<long>(); results[v] = lst; }
                                if (lst.Count < maxPerValue) lst.Add(mbi.BaseAddress + off + i);
                            }
                        }
                    }
                    off += chunk;
                }
            }
            addr = mbi.BaseAddress + mbi.RegionSize;
        }
        Console.WriteLine("total_scanned_bytes=" + totalScanned);
        CloseHandle(h);
        return results;
    }
}
"@

# find all dwords 0x6309xxxx except the original 0x63090551
$match = [Convert]::ToUInt32("64010000", 16)
$mask = [Convert]::ToUInt32("FFFF0000", 16)
$groups = [MaskScan]::ScanDwords($ProcId, $match, $mask, [uint32]0, 8)

$mods = Get-Process -Id $ProcId -Module | ForEach-Object {
    [PSCustomObject]@{ Name = $_.ModuleName; Base = [long]$_.BaseAddress; End = [long]$_.BaseAddress + $_.ModuleMemorySize }
}

Write-Host ("distinct version-like dwords found: " + $groups.Count)
foreach ($kv in $groups.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending) {
    $hexVal = "0x{0:X8}" -f $kv.Key
    $decoded = "{0}.{1}.{2}.{3}" -f (($kv.Key -shr 24) -band 0xFF - 0x60), (($kv.Key -shr 16) -band 0xFF), (($kv.Key -shr 8) -band 0xFF), ($kv.Key -band 0xFF)
    Write-Host ("value " + $hexVal + "  (approx " + $decoded + ")  count~" + $kv.Value.Count)
    foreach ($a in ($kv.Value | Select-Object -First 8)) {
        $m = $mods | Where-Object { $a -ge $_.Base -and $a -lt $_.End } | Select-Object -First 1
        $where = if ($m) { ("{0}+0x{1:X}" -f $m.Name, ($a - $m.Base)) } else { "heap" }
        Write-Host ("    0x{0:X16}  {1}" -f $a, $where)
    }
}
