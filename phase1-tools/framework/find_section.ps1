param(
    [int[]]$Pids = @(11180, 14588, 31432, 7584, 8248),
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

public class SectionFinder {
    [DllImport("ntdll.dll")] static extern int NtQuerySystemInformation(int cls, IntPtr buf, int len, out int ret);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool DuplicateHandle(IntPtr srcProc, IntPtr srcHandle, IntPtr dstProc, out IntPtr dstHandle, int access, bool inherit, int options);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr MapViewOfFile(IntPtr h, int access, uint offHigh, uint offLow, long size);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool UnmapViewOfFile(IntPtr addr);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool FlushViewOfFile(IntPtr addr, long size);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern IntPtr OpenFileMapping(int access, bool inherit, string name);
    [DllImport("ntdll.dll")] static extern int NtQueryObject(IntPtr h, int cls, byte[] buf, int len, out int ret);

    public static List<string> Log = new List<string>();

    static byte[] QuerySystemHandles() {
        int len = 16 * 1024 * 1024;
        IntPtr buf = Marshal.AllocHGlobal(len);
        int ret;
        int st = NtQuerySystemInformation(0x40, buf, len, out ret);
        if (st == unchecked((int)0xC0000004)) { // info length mismatch - grow
            Marshal.FreeHGlobal(buf);
            len = ret + 1024 * 1024;
            buf = Marshal.AllocHGlobal(len);
            st = NtQuerySystemInformation(0x40, buf, len, out ret);
        }
        if (st != 0) { Marshal.FreeHGlobal(buf); Log.Add("NtQuerySystemInformation status=0x" + st.ToString("X8")); return null; }
        byte[] result = new byte[len];
        Marshal.Copy(buf, result, 0, len);
        Marshal.FreeHGlobal(buf);
        return result;
    }

    static string GetSectionName(IntPtr h) {
        try {
            byte[] buf = new byte[4096];
            int ret;
            int st = NtQueryObject(h, 1, buf, buf.Length, out ret); // ObjectNameInformation
            if (st != 0 || ret < 16) return null;
            int len = BitConverter.ToUInt16(buf, 0);
            if (len == 0) return null;
            return Encoding.Unicode.GetString(buf, 16, len);
        } catch { return null; }
    }

    static string GetObjectType(IntPtr h) {
        try {
            byte[] buf = new byte[4096];
            int ret;
            int st = NtQueryObject(h, 2, buf, buf.Length, out ret); // ObjectTypeInformation
            if (st != 0 || ret < 16) return null;
            int len = BitConverter.ToUInt16(buf, 0);
            if (len == 0) return null;
            return Encoding.Unicode.GetString(buf, 16, len);
        } catch { return null; }
    }

    public static string Run(int[] pids, long strOff, string find, string newVer, bool apply) {
        byte[] handles = QuerySystemHandles();
        if (handles == null) return string.Join("\n", Log);
        ulong numHandles = BitConverter.ToUInt64(handles, 0);
        Log.Add("system handles: " + numHandles);
        IntPtr self = GetCurrentProcess();
        int foundWritable = 0;
        int foundReadonly = 0;

        for (int i = 0; i < (int)numHandles; i++) {
            int off = 16 + i * 40;
            if (off + 40 > handles.Length) break;
            ulong pid = BitConverter.ToUInt64(handles, off + 8);
            if (Array.IndexOf(pids, (int)pid) < 0) continue;
            long hv = BitConverter.ToInt64(handles, off + 16);

            IntPtr hp = OpenProcess(0x0040, false, (int)pid); // PROCESS_DUP_HANDLE
            if (hp == IntPtr.Zero) { Log.Add("OpenProcess fail pid=" + pid); continue; }
            IntPtr dup;
            bool ok = DuplicateHandle(hp, (IntPtr)hv, self, out dup, 0, false, 2);
            CloseHandle(hp);
            if (!ok || dup == IntPtr.Zero) continue;

            // identify type (quick, safe for most objects)
            string type = GetObjectType(dup);
            if (type == "Section") {
                // try RW map first
                IntPtr view = MapViewOfFile(dup, 0x0006, 0, 0, 0x1000); // FILE_MAP_READ|FILE_MAP_WRITE
                string mode = "RW";
                if (view == IntPtr.Zero) {
                    view = MapViewOfFile(dup, 0x0004, 0, 0, 0x1000); // FILE_MAP_READ
                    mode = "R";
                }
                if (view != IntPtr.Zero) {
                    byte[] chunk = new byte[64];
                    Marshal.Copy((IntPtr)(view.ToInt64() + strOff), chunk, 0, 64);
                    string s = Encoding.Unicode.GetString(chunk).Split((char)0)[0];
                    if (s == find) {
                        string name = GetSectionName(dup);
                        if (mode == "RW") {
                            foundWritable++;
                            Log.Add("*** WRITABLE SECTION FOUND *** pid=" + pid + " handle=0x" + hv.ToString("X") + " name=" + (name ?? "(anonymous)"));
                            if (apply) {
                                byte[] nb = Encoding.Unicode.GetBytes(newVer);
                                byte[] payload = new byte[nb.Length + 2];
                                Array.Copy(nb, payload, nb.Length);
                                Marshal.Copy(payload, 0, (IntPtr)(view.ToInt64() + strOff), payload.Length);
                                FlushViewOfFile(view, payload.Length);
                                byte[] verify = new byte[64];
                                Marshal.Copy((IntPtr)(view.ToInt64() + strOff), verify, 0, 64);
                                Log.Add("WROTE '" + newVer + "' @ view+0x" + strOff.ToString("X") + " verify: '" + Encoding.Unicode.GetString(verify).Split((char)0)[0] + "'");
                                UnmapViewOfFile(view);
                                CloseHandle(dup);
                                return string.Join("\n", Log);
                            }
                        } else {
                            foundReadonly++;
                            Log.Add("    read-only match: pid=" + pid + " handle=0x" + hv.ToString("X") + " name=" + (name ?? "(anonymous)"));
                        }
                    }
                    UnmapViewOfFile(view);
                }
            }
            CloseHandle(dup);
        }
        Log.Add("done. writable=" + foundWritable + " readonly=" + foundReadonly);
        return string.Join("\n", Log);
    }

    // open by name and write
    public static string OpenByNameAndWrite(string name, long strOff, string find, string newVer) {
        IntPtr h = OpenFileMapping(0x0002 | 0x0004 | 0x0006, false, name); // FILE_MAP_WRITE|READ
        if (h == IntPtr.Zero) return "OpenFileMapping failed err=" + Marshal.GetLastWin32Error() + " name=" + name;
        IntPtr view = MapViewOfFile(h, 0x0006, 0, 0, 0x1000);
        if (view == IntPtr.Zero) { CloseHandle(h); return "MapViewOfFile failed err=" + Marshal.GetLastWin32Error(); }
        byte[] chunk = new byte[64];
        Marshal.Copy((IntPtr)(view.ToInt64() + strOff), chunk, 0, 64);
        string s = Encoding.Unicode.GetString(chunk).Split((char)0)[0];
        if (s != find) { UnmapViewOfFile(view); CloseHandle(h); return "content mismatch: '" + s + "'"; }
        byte[] nb = Encoding.Unicode.GetBytes(newVer);
        byte[] payload = new byte[nb.Length + 2];
        Array.Copy(nb, payload, nb.Length);
        Marshal.Copy(payload, 0, (IntPtr)(view.ToInt64() + strOff), payload.Length);
        FlushViewOfFile(view, payload.Length);
        byte[] check = new byte[64];
        Marshal.Copy((IntPtr)(view.ToInt64() + strOff), check, 0, 64);
        string after = Encoding.Unicode.GetString(check).Split((char)0)[0];
        UnmapViewOfFile(view);
        CloseHandle(h);
        return "after write: '" + after + "' (expected '" + newVer + "')";
    }
}
"@

Write-Host ([SectionFinder]::Run($Pids, $StringOffset, $FindString, $NewVersion, $Apply.IsPresent))
