param(
    [int]$TargetPid = 23428,
    [string]$PatchFrom = "3.9.11.17",
    [string]$PatchTo = "4.1.13.65",
    [int]$MaxHits = 60,
    [int]$RunSeconds = 420,
    [string]$LogFile = "C:\Users\fish\ZCodeProject\ioctl_log2.txt"
)

Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public class MultiHook {
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool DebugActiveProcess(int pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool DebugActiveProcessStop(int pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool DebugSetProcessKillOnExit(bool kill);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool WaitForDebugEvent(byte[] evt, int ms);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool ContinueDebugEvent(int pid, int tid, int status);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenThread(int access, bool inherit, int tid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetThreadContext(IntPtr hThread, IntPtr ctx);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetThreadContext(IntPtr hThread, IntPtr ctx);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadProcessMemory(IntPtr h, long addr, byte[] buf, long size, out long read);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool WriteProcessMemory(IntPtr h, long addr, byte[] buf, long size, out long written);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool VirtualProtectEx(IntPtr h, long addr, long size, int newProtect, out int oldProtect);
    [DllImport("psapi.dll", SetLastError=true)] static extern bool EnumProcessModulesEx(IntPtr h, IntPtr[] mods, int cb, out int needed, int filter);
    [DllImport("psapi.dll", CharSet=CharSet.Unicode)] static extern int GetModuleBaseName(IntPtr h, IntPtr mod, StringBuilder name, int size);
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi)] static extern IntPtr GetModuleHandleA(string name);
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi)] static extern IntPtr GetProcAddress(IntPtr mod, string name);

    const int DBG_CONTINUE = 0x00010002;
    const int CTX_FLAGS = 0x30, CTX_EFLAGS = 0x44, CTX_RCX = 0x80, CTX_RDX = 0x88, CTX_RSP = 0x98, CTX_R8 = 0xB8, CTX_R9 = 0xC0, CTX_RIP = 0xF8;
    const uint CONTEXT_FULL = 0x0010000B;

    static StreamWriter log;
    static void L(string s) { log.WriteLine(DateTime.Now.ToString("HH:mm:ss.fff") + " " + s); log.Flush(); }

    static long ResolveFunc(IntPtr proc, string fname, out long ntdllBase) {
        ntdllBase = 0;
        IntPtr[] mods = new IntPtr[1024];
        int needed;
        if (!EnumProcessModulesEx(proc, mods, mods.Length * IntPtr.Size, out needed, 0x03)) return 0;
        int count = needed / IntPtr.Size;
        for (int i = 0; i < count && i < 1024; i++) {
            StringBuilder sb = new StringBuilder(260);
            GetModuleBaseName(proc, mods[i], sb, 260);
            if (sb.ToString().ToLowerInvariant() == "ntdll.dll") { ntdllBase = (long)mods[i]; break; }
        }
        if (ntdllBase == 0) return 0;
        IntPtr myNtdll = GetModuleHandleA("ntdll.dll");
        IntPtr myFunc = GetProcAddress(myNtdll, fname);
        if (myFunc == IntPtr.Zero) return 0;
        return ntdllBase + ((long)myFunc - (long)myNtdll);
    }

    static bool WriteCodeByte(IntPtr proc, long addr, byte val, out string err) {
        err = null;
        int oldProt;
        if (!VirtualProtectEx(proc, addr, 16, 0x40, out oldProt)) { err = "VPX err=" + Marshal.GetLastWin32Error(); return false; }
        byte[] b = new byte[] { val }; long w;
        bool ok = WriteProcessMemory(proc, addr, b, 1, out w);
        int dummy;
        VirtualProtectEx(proc, addr, 16, oldProt, out dummy);
        if (!ok) { err = "WPM err=" + Marshal.GetLastWin32Error(); return false; }
        return true;
    }

    static string HexDump(byte[] b, int off, int len) {
        var sb = new StringBuilder();
        for (int i = off; i < off + len && i < b.Length; i++) sb.Append(b[i].ToString("X2") + " ");
        return sb.ToString();
    }

    static int FindStr(byte[] buf, byte[] u16, byte[] asc, out int mode) {
        mode = 0;
        for (int i = 0; i + u16.Length <= buf.Length; i++) {
            bool m = true;
            for (int j = 0; j < u16.Length; j++) if (buf[i + j] != u16[j]) { m = false; break; }
            if (m) return i;
        }
        mode = 1;
        for (int i = 0; i + asc.Length <= buf.Length; i++) {
            bool m = true;
            for (int j = 0; j < asc.Length; j++) if (buf[i + j] != asc[j]) { m = false; break; }
            if (m) return i;
        }
        return -1;
    }

    public static string Run(int pid, string from, string to, int maxHits, int runSeconds, string logFile) {
        log = new StreamWriter(logFile, false);
        try {
            IntPtr proc = OpenProcess(0x0438, false, pid);
            if (proc == IntPtr.Zero) { L("OpenProcess failed"); return "FAIL"; }

            string[] funcs = new string[] { "NtCreateFile", "NtWriteFile", "NtFsControlFile", "NtDeviceIoControlFile" };
            var bpAddrs = new List<long>();
            var bpNames = new List<string>();
            var bpOrig = new List<byte>();
            var bpSet = new List<bool>();

            long dummyBase;
            foreach (string f in funcs) {
                long a = ResolveFunc(proc, f, out dummyBase);
                bpAddrs.Add(a); bpNames.Add(f); bpOrig.Add(0); bpSet.Add(false);
                if (a == 0) { L("resolve " + f + " FAILED"); continue; }
                byte[] orig = new byte[1]; long got;
                ReadProcessMemory(proc, a, orig, 1, out got);
                bpOrig[bpOrig.Count - 1] = orig[0];
                string err;
                if (!WriteCodeByte(proc, a, 0xCC, out err)) { L("bp " + f + " FAILED: " + err); continue; }
                bpSet[bpSet.Count - 1] = true;
                L("bp set on " + f + " @ 0x" + a.ToString("X") + " (orig 0x" + orig[0].ToString("X2") + ")");
            }

            if (!DebugActiveProcess(pid)) { L("DebugActiveProcess failed err=" + Marshal.GetLastWin32Error()); return "FAIL"; }
            DebugSetProcessKillOnExit(false);
            L("debugger attached; waiting for calls...");

            byte[] evt = new byte[256];
            int hits = 0;
            DateTime start = DateTime.Now;
            byte[] fromU = Encoding.Unicode.GetBytes(from);
            byte[] toU = Encoding.Unicode.GetBytes(to);
            byte[] fromA = Encoding.ASCII.GetBytes(from);
            byte[] toA = Encoding.ASCII.GetBytes(to);
            long pendingRearm = 0; // address to re-arm after single-step

            while ((DateTime.Now - start).TotalSeconds < runSeconds && hits < maxHits) {
                if (!WaitForDebugEvent(evt, 1000)) continue;
                int code = BitConverter.ToInt32(evt, 0);
                int epid = BitConverter.ToInt32(evt, 4);
                int tid = BitConverter.ToInt32(evt, 8);

                if (code == 1) {
                    int excCode = BitConverter.ToInt32(evt, 12);
                    long excAddr = BitConverter.ToInt64(evt, 28);

                    if (excCode == unchecked((int)0x80000003)) {
                        // which bp?
                        int bi = -1;
                        for (int i = 0; i < bpAddrs.Count; i++) if (bpSet[i] && bpAddrs[i] == excAddr) { bi = i; break; }
                        if (bi < 0) { ContinueDebugEvent(epid, tid, DBG_CONTINUE); continue; }

                        hits++;
                        IntPtr ht = OpenThread(0x1FFFFF, false, tid);
                        IntPtr ctx = Marshal.AllocHGlobal(1232);
                        for (int i = 0; i < 1232; i++) Marshal.WriteByte(ctx, i, 0);
                        Marshal.WriteInt32(ctx, CTX_FLAGS, unchecked((int)CONTEXT_FULL));
                        GetThreadContext(ht, ctx);
                        long rcx = Marshal.ReadInt64(ctx, CTX_RCX);
                        long r9 = Marshal.ReadInt64(ctx, CTX_R9);
                        long rsp = Marshal.ReadInt64(ctx, CTX_RSP);
                        byte[] p8 = new byte[8]; long g2;

                        string fname = bpNames[bi];
                        if (fname == "NtCreateFile") {
                            // r9 = POBJECT_ATTRIBUTES; ObjectName at +16; UNICODE_STRING Buffer at +8
                            ReadProcessMemory(proc, r9 + 16, p8, 8, out g2);
                            long uni = BitConverter.ToInt64(p8, 0);
                            if (uni != 0) {
                                ReadProcessMemory(proc, uni, p8, 8, out g2);
                                int nlen = BitConverter.ToInt16(p8, 0);
                                long nbuf = BitConverter.ToInt64(p8, 8);
                                if (nlen > 0 && nlen < 1024) {
                                    byte[] nb = new byte[nlen]; long g3;
                                    if (ReadProcessMemory(proc, nbuf, nb, nlen, out g3))
                                        L("HIT #" + hits + " " + fname + " -> OPEN: '" + Encoding.Unicode.GetString(nb) + "'");
                                } else L("HIT #" + hits + " " + fname + " (name len odd)");
                            } else L("HIT #" + hits + " " + fname + " (no name)");
                        } else {
                            // generic: buffer/len at rsp+0x30/+0x38, extra code at rsp+0x50
                            ReadProcessMemory(proc, rsp + 0x30, p8, 8, out g2); long bufPtr = BitConverter.ToInt64(p8, 0);
                            ReadProcessMemory(proc, rsp + 0x38, p8, 8, out g2); long bufLen = BitConverter.ToInt64(p8, 0);
                            ReadProcessMemory(proc, rsp + 0x50, p8, 8, out g2); long code10 = BitConverter.ToInt64(p8, 0);
                            L("HIT #" + hits + " " + fname + " handle=0x" + rcx.ToString("X") + " code=0x" + code10.ToString("X") + " buf=0x" + bufPtr.ToString("X") + " len=" + bufLen);
                            if (bufPtr != 0 && bufLen > 0 && bufLen < 1024 * 1024) {
                                int readN = (int)Math.Min(bufLen, 65536);
                                byte[] buf = new byte[readN]; long g3;
                                if (ReadProcessMemory(proc, bufPtr, buf, readN, out g3)) {
                                    L("   head: " + HexDump(buf, 0, Math.Min(readN, 96)));
                                    int mode;
                                    int pos = FindStr(buf, fromU, fromA, out mode);
                                    if (pos >= 0) {
                                        L("   FOUND '" + from + "' at buf+0x" + pos.ToString("X") + " (" + (mode == 0 ? "utf16" : "ascii") + ")");
                                        byte[] repl = mode == 0 ? toU : toA;
                                        long w2;
                                        if (WriteProcessMemory(proc, bufPtr + pos, repl, repl.Length, out w2))
                                            L("   *** PATCHED to '" + to + "' ***");
                                        else
                                            L("   patch FAILED err=" + Marshal.GetLastWin32Error());
                                    } else {
                                        // scan whole payload for any 3.9.x-like string to understand format
                                        string txt = Encoding.Unicode.GetString(buf, 0, Math.Min(readN, 2048));
                                        var sb2 = new StringBuilder();
                                        foreach (char c in txt) sb2.Append(c >= 0x20 && c < 0x7f ? c : '.');
                                        L("   no target string; payload preview: " + sb2.ToString());
                                    }
                                } else L("   read buffer failed");
                            }
                        }

                        // restore, rewind, TF single-step
                        string e2;
                        WriteCodeByte(proc, bpAddrs[bi], bpOrig[bi], out e2);
                        pendingRearm = bpAddrs[bi];
                        Marshal.WriteInt64(ctx, CTX_RIP, excAddr);
                        int ef = Marshal.ReadInt32(ctx, CTX_EFLAGS);
                        Marshal.WriteInt32(ctx, CTX_EFLAGS, ef | 0x100);
                        SetThreadContext(ht, ctx);
                        Marshal.FreeHGlobal(ctx);
                        CloseHandle(ht);
                        ContinueDebugEvent(epid, tid, DBG_CONTINUE);
                        continue;
                    }

                    if (excCode == unchecked((int)0x80000004)) {
                        if (pendingRearm != 0) {
                            string e3;
                            WriteCodeByte(proc, pendingRearm, 0xCC, out e3);
                            pendingRearm = 0;
                        }
                        IntPtr ht2 = OpenThread(0x1FFFFF, false, tid);
                        if (ht2 != IntPtr.Zero) {
                            IntPtr ctx2 = Marshal.AllocHGlobal(1232);
                            for (int i = 0; i < 1232; i++) Marshal.WriteByte(ctx2, i, 0);
                            Marshal.WriteInt32(ctx2, CTX_FLAGS, unchecked((int)CONTEXT_FULL));
                            GetThreadContext(ht2, ctx2);
                            int ef2 = Marshal.ReadInt32(ctx2, CTX_EFLAGS);
                            Marshal.WriteInt32(ctx2, CTX_EFLAGS, ef2 & ~0x100);
                            SetThreadContext(ht2, ctx2);
                            Marshal.FreeHGlobal(ctx2);
                            CloseHandle(ht2);
                        }
                        ContinueDebugEvent(epid, tid, DBG_CONTINUE);
                        continue;
                    }

                    ContinueDebugEvent(epid, tid, DBG_CONTINUE);
                    continue;
                }

                ContinueDebugEvent(epid, tid, DBG_CONTINUE);
            }

            for (int i = 0; i < bpAddrs.Count; i++) {
                if (bpSet[i]) { string e4; WriteCodeByte(proc, bpAddrs[i], bpOrig[i], out e4); }
            }
            DebugActiveProcessStop(pid);
            L("done. hits=" + hits);
            return "OK hits=" + hits;
        } catch (Exception e) {
            L("EXCEPTION: " + e.ToString());
            return "EXC: " + e.Message;
        } finally {
            if (log != null) log.Close();
        }
    }
}
"@

Write-Host ("multi interceptor: pid=" + $TargetPid + " " + $PatchFrom + " -> " + $PatchTo)
$result = [MultiHook]::Run($TargetPid, $PatchFrom, $PatchTo, $MaxHits, $RunSeconds, $LogFile)
Write-Host ("RESULT: " + $result)
