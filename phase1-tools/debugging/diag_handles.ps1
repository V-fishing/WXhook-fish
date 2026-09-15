param([int[]]$Pids = @(11180, 14588, 31432, 7584, 8248))

Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public class SectionDiag {
    [DllImport("ntdll.dll")] static extern int NtQuerySystemInformation(int cls, IntPtr buf, int len, out int ret);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool DuplicateHandle(IntPtr srcProc, IntPtr srcHandle, IntPtr dstProc, out IntPtr dstHandle, int access, bool inherit, int options);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr MapViewOfFile(IntPtr h, int access, uint offHigh, uint offLow, long size);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool UnmapViewOfFile(IntPtr addr);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("ntdll.dll")] static extern int NtQueryObject(IntPtr h, int cls, byte[] buf, int len, out int ret);

    public static List<string> Log = new List<string>();

    static string QName(IntPtr h, int cls) {
        try {
            byte[] buf = new byte[8192];
            int ret;
            int st = NtQueryObject(h, cls, buf, buf.Length, out ret);
            if (st != 0) return "QObjErr0x" + st.ToString("X");
            int len = BitConverter.ToUInt16(buf, 0);
            if (len == 0) return "(noname)";
            return Encoding.Unicode.GetString(buf, 16, len);
        } catch (Exception e) { return "exc:" + e.GetType().Name; }
    }

    public static string Run(int[] pids) {
        int len = 32 * 1024 * 1024;
        IntPtr buf = Marshal.AllocHGlobal(len);
        int ret;
        int st = NtQuerySystemInformation(0x40, buf, len, out ret);
        if (st != 0) { Marshal.FreeHGlobal(buf); return "NtQuerySysInfo st=0x" + st.ToString("X8"); }
        byte[] data = new byte[len];
        Marshal.Copy(buf, data, 0, len);
        Marshal.FreeHGlobal(buf);
        ulong n = BitConverter.ToUInt64(data, 0);
        Log.Add("handles=" + n);

        IntPtr self = GetCurrentProcess();
        int dupTry = 0, dupOk = 0, typeOk = 0;
        var typeCount = new Dictionary<string,int>();
        var sections = new List<string>();

        for (int i = 0; i < (int)n; i++) {
            int off = 16 + i * 40;
            if (off + 40 > len) break;
            ulong pid = BitConverter.ToUInt64(data, off + 8);
            if (Array.IndexOf(pids, (int)pid) < 0) continue;
            long hv = BitConverter.ToInt64(data, off + 16);
            dupTry++;
            IntPtr hp = OpenProcess(0x0040, false, (int)pid);
            if (hp == IntPtr.Zero) { continue; }
            IntPtr dup;
            bool ok = DuplicateHandle(hp, (IntPtr)hv, self, out dup, 0, false, 2);
            CloseHandle(hp);
            if (!ok) continue;
            dupOk++;
            string type = QName(dup, 2); // ObjectTypeInformation
            if (type != null && !type.StartsWith("QObjErr")) typeOk++;
            if (typeCount.ContainsKey(type ?? "null")) typeCount[type ?? "null"]++; else typeCount[type ?? "null"] = 1;
            if (type == "Section") {
                string name = QName(dup, 1); // ObjectNameInformation
                IntPtr view = MapViewOfFile(dup, 0x0004, 0, 0, 0x1000);
                string content = "(map fail err=" + Marshal.GetLastWin32Error() + ")";
                if (view != IntPtr.Zero) {
                    byte[] chunk = new byte[40];
                    Marshal.Copy((IntPtr)(view.ToInt64() + 0xE30), chunk, 0, 40);
                    content = "'" + Encoding.Unicode.GetString(chunk).Split((char)0)[0] + "'";
                    UnmapViewOfFile(view);
                }
                sections.Add("pid=" + pid + " h=0x" + hv.ToString("X") + " name=" + name + " @E30=" + content);
            }
            CloseHandle(dup);
        }
        Log.Add("target-handles=" + dupTry + " dupOK=" + dupOk + " typeQueryOK=" + typeOk);
        foreach (var kv in typeCount) Log.Add("  type " + kv.Key + " x" + kv.Value);
        Log.Add("--- sections (first 40) ---");
        foreach (var s in sections) Log.Add("  " + s);
        return string.Join("\n", Log);
    }
}
"@

Write-Host ([SectionDiag]::Run($Pids))
