param(
    [string]$FindString = "3.9.11.17",
    [string]$NewVersion = "4.1.13.65",
    [long]$ScanBytes = 4194304,
    [switch]$Apply
)

Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

public class FullSectionHunt {
    [DllImport("ntdll.dll")] static extern int NtQuerySystemInformation(int cls, IntPtr buf, int len, out int ret);
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll")] static extern bool DuplicateHandle(IntPtr srcProc, IntPtr srcHandle, IntPtr dstProc, out IntPtr dstHandle, int access, bool inherit, int options);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] static extern IntPtr MapViewOfFile(IntPtr h, int access, uint offHigh, uint offLow, long size);
    [DllImport("kernel32.dll")] static extern bool UnmapViewOfFile(IntPtr addr);
    [DllImport("kernel32.dll")] static extern bool FlushViewOfFile(IntPtr addr, long size);
    [DllImport("kernel32.dll", SetLastError=true)] static extern long VirtualQuery(IntPtr addr, out MEMORY_BASIC_INFORMATION info, int len);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public long BaseAddress; public long AllocationBase; public int AllocationProtect; public int __a1;
        public long RegionSize; public int State; public int Protect; public int Type; public int __a2;
    }

    public static List<string> Log = new List<string>();

    static bool IsTarget(string name) {
        string n = name.ToLowerInvariant();
        return n.Contains("wechat") || n.Contains("weixin") || name.Contains("微信") || n.Contains("tencent");
    }

    public static string Run(string find, string newVer, long scanBytes, bool apply) {
        // build pid set
        var pids = new HashSet<int>();
        foreach (var p in Process.GetProcesses()) {
            try { if (IsTarget(p.ProcessName) || p.ProcessName.Contains("微信")) pids.Add(p.Id); } catch {}
        }
        pids.Add(10448); // the bypass tool
        Log.Add("target pids: " + string.Join(",", pids));

        int len = 32 * 1024 * 1024;
        IntPtr buf = Marshal.AllocHGlobal(len);
        int ret;
        int st = NtQuerySystemInformation(0x40, buf, len, out ret);
        if (st != 0) { Marshal.FreeHGlobal(buf); return "NtQuerySystemInformation st=0x" + st.ToString("X8"); }
        byte[] data = new byte[len];
        Marshal.Copy(buf, data, 0, len);
        Marshal.FreeHGlobal(buf);
        ulong n = BitConverter.ToUInt64(data, 0);
        Log.Add("system handles: " + n);

        byte[] pat = Encoding.Unicode.GetBytes(find);
        IntPtr self = GetCurrentProcess();
        int mapped = 0;

        for (int i = 0; i < (int)n; i++) {
            int off = 16 + i * 40;
            if (off + 40 > len) break;
            ulong pid = BitConverter.ToUInt64(data, off + 8);
            if (!pids.Contains((int)pid)) continue;
            long hv = BitConverter.ToInt64(data, off + 16);

            IntPtr hp = OpenProcess(0x0040, false, (int)pid);
            if (hp == IntPtr.Zero) continue;
            IntPtr dup;
            bool ok = DuplicateHandle(hp, (IntPtr)hv, self, out dup, 0, false, 2);
            CloseHandle(hp);
            if (!ok) continue;

            foreach (int access in new int[] { 0x0006, 0x0004 }) {
                IntPtr view = MapViewOfFile(dup, access, 0, 0, 0); // map entire section
                if (view == IntPtr.Zero) continue;
                mapped++;
                long baseAddr = view.ToInt64();
                // determine real view size
                var mbi = new MEMORY_BASIC_INFORMATION();
                long viewSize = scanBytes;
                if (VirtualQuery(view, out mbi, Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) != 0 && mbi.RegionSize > 0) {
                    viewSize = Math.Min(mbi.RegionSize, scanBytes);
                }
                // scan in 1MB chunks
                byte[] chunk = new byte[1 << 20];
                long limit = viewSize;
                for (long o = 0; o < limit; o += chunk.Length) {
                    int readLen = (int)Math.Min(chunk.Length, limit - o);
                    try {
                        Marshal.Copy((IntPtr)(baseAddr + o), chunk, 0, readLen);
                    } catch { break; }
                    for (int k = 0; k + pat.Length <= readLen; k++) {
                        bool hit = true;
                        for (int j = 0; j < pat.Length; j++) { if (chunk[k + j] != pat[j]) { hit = false; break; } }
                        if (hit) {
                            long foundOff = o + k;
                            string rw = access == 0x0006 ? "WRITABLE" : "readonly";
                            Log.Add("MATCH (" + rw + "): pid=" + pid + " handle=0x" + hv.ToString("X") + " sectionOffset=0x" + foundOff.ToString("X"));
                            if (access == 0x0006 && apply) {
                                byte[] nb = Encoding.Unicode.GetBytes(newVer);
                                byte[] payload = new byte[nb.Length + 2];
                                Array.Copy(nb, payload, nb.Length);
                                Marshal.Copy(payload, 0, (IntPtr)(baseAddr + foundOff), payload.Length);
                                FlushViewOfFile((IntPtr)(baseAddr + foundOff), payload.Length);
                                byte[] verify = new byte[64];
                                Marshal.Copy((IntPtr)(baseAddr + foundOff), verify, 0, 64);
                                Log.Add("WROTE '" + newVer + "' verify: '" + Encoding.Unicode.GetString(verify).Split((char)0)[0] + "'");
                                UnmapViewOfFile(view);
                                CloseHandle(dup);
                                Log.Add("total mapped: " + mapped);
                                return string.Join("\n", Log);
                            }
                            o = limit; break;
                        }
                    }
                }
                UnmapViewOfFile(view);
                if (Log.Count > 0 && Log[Log.Count - 1].StartsWith("MATCH")) break;
            }
            CloseHandle(dup);
        }
        Log.Add("done. mapped=" + mapped + " no " + (apply ? "writable " : "") + "match");
        return string.Join("\n", Log);
    }
}
"@

Write-Host ([FullSectionHunt]::Run($FindString, $NewVersion, $ScanBytes, $Apply.IsPresent))
