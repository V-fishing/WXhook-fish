param(
    [int[]]$Pids = @(10448, 22748, 11180),
    [long]$StringOffset = 0xE30,
    [string]$FindString = "3.9.11.17",
    [string]$NewVersion = "4.1.13.65",
    [switch]$Apply
)

Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public class BlindSectionFinder {
    [DllImport("ntdll.dll")] static extern int NtQuerySystemInformation(int cls, IntPtr buf, int len, out int ret);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool DuplicateHandle(IntPtr srcProc, IntPtr srcHandle, IntPtr dstProc, out IntPtr dstHandle, int access, bool inherit, int options);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr MapViewOfFile(IntPtr h, int access, uint offHigh, uint offLow, long size);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool UnmapViewOfFile(IntPtr addr);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool FlushViewOfFile(IntPtr addr, long size);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("ntdll.dll")] static extern int NtQueryObject(IntPtr h, int cls, byte[] buf, int len, out int ret);

    public static List<string> Log = new List<string>();

    static string QNameSafe(IntPtr h) {
        try {
            byte[] buf = new byte[8192];
            int ret;
            int st = NtQueryObject(h, 1, buf, buf.Length, out ret);
            if (st != 0) return null;
            int len = (int)BitConverter.ToUInt16(buf, 0);
            if (len == 0) return null;
            // string follows the UNICODE_STRING struct (offset 16), but confirm by scanning
            for (int probe = 16; probe <= 64 && probe + len <= buf.Length; probe += 8) {
                string cand = Encoding.Unicode.GetString(buf, probe, len);
                bool ok = true;
                foreach (char c in cand) { if (c < 0x20 || c > 0x7e) { ok = false; break; } }
                if (ok) return cand;
            }
            return null;
        } catch { return null; }
    }

    public static string Run(int[] pids, long strOff, string find, string newVer, bool apply) {
        int len = 32 * 1024 * 1024;
        IntPtr buf = Marshal.AllocHGlobal(len);
        int ret;
        int st = NtQuerySystemInformation(0x40, buf, len, out ret);
        if (st != 0) { Marshal.FreeHGlobal(buf); return "NtQuerySystemInformation st=0x" + st.ToString("X8"); }
        byte[] data = new byte[len];
        Marshal.Copy(buf, data, 0, len);
        Marshal.FreeHGlobal(buf);
        ulong n = BitConverter.ToUInt64(data, 0);

        IntPtr self = GetCurrentProcess();
        long mappedOk = 0, rwMapped = 0, roMapped = 0, matchRW = 0, matchRO = 0;

        byte[] findBytes = Encoding.Unicode.GetBytes(find);
        int findChars = find.Length;

        for (int i = 0; i < (int)n; i++) {
            int off = 16 + i * 40;
            if (off + 40 > len) break;
            ulong pid = BitConverter.ToUInt64(data, off + 8);
            if (Array.IndexOf(pids, (int)pid) < 0) continue;
            long hv = BitConverter.ToInt64(data, off + 16);

            IntPtr hp = OpenProcess(0x0040, false, (int)pid);
            if (hp == IntPtr.Zero) continue;
            IntPtr dup;
            bool ok = DuplicateHandle(hp, (IntPtr)hv, self, out dup, 0, false, 2);
            CloseHandle(hp);
            if (!ok) continue;

            foreach (int access in new int[] { 0x0006, 0x0004 }) { // RW then R
                IntPtr view = MapViewOfFile(dup, access, 0, 0, 0x1000);
                if (view == IntPtr.Zero) continue;
                mappedOk++;
                if (access == 0x0006) rwMapped++; else roMapped++;
                byte[] chunk = new byte[findBytes.Length + 4];
                Marshal.Copy((IntPtr)(view.ToInt64() + strOff), chunk, 0, chunk.Length);
                string s = Encoding.Unicode.GetString(chunk).Split((char)0)[0];
                bool hit = s == find;
                if (hit) {
                    string name = QNameSafe(dup);
                    if (access == 0x0006) {
                        matchRW++;
                        Log.Add("MATCH+WRITABLE: pid=" + pid + " handle=0x" + hv.ToString("X") + " name=" + (name ?? "(unknown)"));
                        if (apply) {
                            byte[] nb = Encoding.Unicode.GetBytes(newVer);
                            byte[] payload = new byte[nb.Length + 2];
                            Array.Copy(nb, payload, nb.Length);
                            Marshal.Copy(payload, 0, (IntPtr)(view.ToInt64() + strOff), payload.Length);
                            FlushViewOfFile(view, payload.Length);
                            byte[] verify = new byte[64];
                            Marshal.Copy((IntPtr)(view.ToInt64() + strOff), verify, 0, 64);
                            Log.Add("WROTE '" + newVer + "' -> verify: '" + Encoding.Unicode.GetString(verify).Split((char)0)[0] + "'");
                            UnmapViewOfFile(view);
                            CloseHandle(dup);
                            Log.Add("stats: mapped=" + mappedOk + " rw=" + rwMapped + " ro=" + roMapped);
                            return string.Join("\n", Log);
                        }
                    } else {
                        matchRO++;
                        Log.Add("match (read-only view): pid=" + pid + " handle=0x" + hv.ToString("X") + " name=" + (name ?? "(unknown)"));
                    }
                }
                UnmapViewOfFile(view);
                if (hit) break; // don't try R after RW hit on same handle
            }
            CloseHandle(dup);
        }
        Log.Add("done. mapped=" + mappedOk + " (rw=" + rwMapped + " ro=" + roMapped + ") matchRW=" + matchRW + " matchRO=" + matchRO);
        return string.Join("\n", Log);
    }
}
"@

Write-Host ([BlindSectionFinder]::Run($Pids, $StringOffset, $FindString, $NewVersion, $Apply.IsPresent))
