param(
    [string]$FindString = "3.9.11.17",
    [string]$NewVersion = "4.1.13.65",
    [long]$ScanBytes = 8388608,
    [switch]$Apply
)

Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public class NamedSectionHunt {
    [DllImport("ntdll.dll")] static extern int NtOpenDirectoryObject(out IntPtr h, int access, ref OBJECT_ATTRIBUTES oa);
    [DllImport("ntdll.dll")] static extern int NtQueryDirectoryObject(IntPtr h, byte[] buf, int len, bool single, bool restart, ref int ctx, out int ret);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern IntPtr OpenFileMapping(int access, bool inherit, string name);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr MapViewOfFile(IntPtr h, int access, uint offHigh, uint offLow, long size);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool UnmapViewOfFile(IntPtr addr);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool FlushViewOfFile(IntPtr addr, long size);
    [DllImport("kernel32.dll", SetLastError=true)] static extern long VirtualQuery(IntPtr addr, out MEMORY_BASIC_INFORMATION info, int len);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);

    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES {
        public int Length; public IntPtr RootDirectory; public IntPtr ObjectName; public int Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public long BaseAddress; public long AllocationBase; public int AllocationProtect; public int __a1;
        public long RegionSize; public int State; public int Protect; public int Type; public int __a2;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING {
        public ushort Length; public ushort MaximumLength; public IntPtr Buffer;
    }

    public static List<string> Log = new List<string>();

    // enumerate directory object names of a given type
    static List<string>[] EnumDir(string dirName) {
        var names = new List<string>();
        var types = new List<string>();
        // build object attributes for the directory
        IntPtr nameBuf = Marshal.StringToHGlobalUni(dirName);
        var us = new UNICODE_STRING();
        us.Length = (ushort)(dirName.Length * 2);
        us.MaximumLength = (ushort)(dirName.Length * 2 + 2);
        us.Buffer = nameBuf;
        IntPtr usBuf = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
        Marshal.StructureToPtr(us, usBuf, false);
        var oa = new OBJECT_ATTRIBUTES();
        oa.Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
        oa.ObjectName = usBuf;
        IntPtr hDir;
        int st = NtOpenDirectoryObject(out hDir, 0x0001, ref oa); // DIRECTORY_QUERY
        Marshal.FreeHGlobal(usBuf);
        Marshal.FreeHGlobal(nameBuf);
        if (st != 0) { Log.Add("NtOpenDirectoryObject(" + dirName + ") st=0x" + st.ToString("X8")); return new List<string>[] { names, types }; }

        int ctx = 0;
        int ret;
        byte[] buf = new byte[64 * 1024];
        while (true) {
            st = NtQueryDirectoryObject(hDir, buf, buf.Length, true, false, ref ctx, out ret);
            if (st != 0) break;
            // parse one entry: OBJECT_DIRECTORY_INFORMATION { UNICODE_STRING Name; UNICODE_STRING Type; } + inline strings
            ushort nLen = BitConverter.ToUInt16(buf, 0);
            ushort tLen = BitConverter.ToUInt16(buf, 16);
            if (nLen == 0) break;
            int nameOff = 64;
            int typeOff = 64 + nLen + 2;
            string objName = Encoding.Unicode.GetString(buf, nameOff, nLen);
            string objType = tLen > 2 ? Encoding.Unicode.GetString(buf, typeOff, tLen - 2) : "";
            names.Add(objName); types.Add(objType);
        }
        CloseHandle(hDir);
        return new List<string>[] { names, types };
    }

    public static string Run(string find, string newVer, long scanBytes, bool apply) {
        string[] dirs = new string[] { @"\Sessions\1\BaseNamedObjects", @"\BaseNamedObjects", @"\Sessions\1\AppContainerNamedObjects" };
        byte[] pat = Encoding.Unicode.GetBytes(find);
        int totalSections = 0, opened = 0, matched = 0;

        foreach (string dir in dirs) {
            var res = EnumDir(dir);
            var names = res[0]; var types = res[1];
            Log.Add("dir " + dir + ": " + names.Count + " objects");
            var typeHist = new Dictionary<string,int>();
            for (int x = 0; x < types.Count; x++) {
                string t = types[x] ?? "(null)";
                if (typeHist.ContainsKey(t)) typeHist[t]++; else typeHist[t] = 1;
            }
            var histLine = new List<string>();
            foreach (var kv in typeHist) histLine.Add(kv.Key + "=" + kv.Value);
            Log.Add("  types: " + string.Join(", ", histLine));
            for (int s = 0; s < Math.Min(8, names.Count); s++) Log.Add("  sample: [" + types[s] + "] " + names[s]);
            for (int i = 0; i < names.Count; i++) {
                if (!types[i].StartsWith("Sectio")) continue;
                totalSections++;
                // full path for OpenFileMapping
                string objName = names[i];
                string fullName = dir.StartsWith(@"\BaseNamedObjects") ? ("Global\\" + objName) : objName;
                IntPtr h = OpenFileMapping(0x0006, false, fullName); // RW
                bool rw = true;
                if (h == IntPtr.Zero) { h = OpenFileMapping(0x0004, false, fullName); rw = false; }
                if (h == IntPtr.Zero) continue;
                opened++;
                IntPtr view = MapViewOfFile(h, rw ? 0x0006 : 0x0004, 0, 0, 0);
                if (view == IntPtr.Zero) { CloseHandle(h); continue; }
                var mbi = new MEMORY_BASIC_INFORMATION();
                long viewSize = scanBytes;
                if (VirtualQuery(view, out mbi, Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) != 0 && mbi.RegionSize > 0)
                    viewSize = Math.Min(mbi.RegionSize, scanBytes);
                long baseAddr = view.ToInt64();
                byte[] chunk = new byte[1 << 20];
                bool hit = false;
                for (long o = 0; o < viewSize && !hit; o += chunk.Length) {
                    int readLen = (int)Math.Min(chunk.Length, viewSize - o);
                    try { Marshal.Copy((IntPtr)(baseAddr + o), chunk, 0, readLen); } catch { break; }
                    for (int k = 0; k + pat.Length <= readLen; k++) {
                        bool m = true;
                        for (int j = 0; j < pat.Length; j++) { if (chunk[k + j] != pat[j]) { m = false; break; } }
                        if (m) {
                            hit = true;
                            matched++;
                            long foundOff = o + k;
                            Log.Add("MATCH: name=" + fullName + " (" + (rw ? "RW" : "RO") + ") offset=0x" + foundOff.ToString("X") + " size=0x" + viewSize.ToString("X"));
                            if (rw && apply) {
                                byte[] nb = Encoding.Unicode.GetBytes(newVer);
                                byte[] payload = new byte[nb.Length + 2];
                                Array.Copy(nb, payload, nb.Length);
                                Marshal.Copy(payload, 0, (IntPtr)(baseAddr + foundOff), payload.Length);
                                FlushViewOfFile((IntPtr)(baseAddr + foundOff), payload.Length);
                                byte[] verify = new byte[64];
                                Marshal.Copy((IntPtr)(baseAddr + foundOff), verify, 0, 64);
                                Log.Add("WROTE '" + newVer + "' verify: '" + Encoding.Unicode.GetString(verify).Split((char)0)[0] + "'");
                                UnmapViewOfFile(view); CloseHandle(h);
                                return string.Join("\n", Log);
                            }
                            break;
                        }
                    }
                }
                UnmapViewOfFile(view);
                CloseHandle(h);
            }
        }
        Log.Add("done. sections=" + totalSections + " opened=" + opened + " matched=" + matched);
        return string.Join("\n", Log);
    }
}
"@

Write-Host ([NamedSectionHunt]::Run($FindString, $NewVersion, $ScanBytes, $Apply.IsPresent))
