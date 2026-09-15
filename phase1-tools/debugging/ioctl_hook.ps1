param(
    [int]$TargetPid = 23428,
    [string]$PatchFrom = "3.9.11.17",
    [string]$PatchTo = "4.1.13.65",
    [int]$MaxHits = 20,
    [int]$RunSeconds = 300,
    [string]$LogFile = "C:\Users\fish\ZCodeProject\ioctl_log.txt"
)

Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public class IoctlHook {
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
    [DllImport("psapi.dll", SetLastError=true)] static extern bool EnumProcessModulesEx(IntPtr h, IntPtr[] mods, int cb, out int needed, int filter);
    [DllImport("psapi.dll", CharSet=CharSet.Unicode)] static extern int GetModuleBaseName(IntPtr h, IntPtr mod, StringBuilder name, int size);
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi)] static extern IntPtr GetModuleHandleA(string name);
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi)] static extern IntPtr GetProcAddress(IntPtr mod, string name);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool VirtualProtectEx(IntPtr h, long addr, long size, int newProtect, out int oldProtect);

    // write 0xCC / restore byte with page protection juggling
    static bool WriteCodeByte(IntPtr proc, long addr, byte val, out string err) {
        err = null;
        int oldProt;
        if (!VirtualProtectEx(proc, addr, 16, 0x40, out oldProt)) { err = "VirtualProtectEx failed err=" + Marshal.GetLastWin32Error(); return false; }
        byte[] b = new byte[] { val }; long w;
        bool ok = WriteProcessMemory(proc, addr, b, 1, out w);
        int dummy;
        VirtualProtectEx(proc, addr, 16, oldProt, out dummy);
        if (!ok) { err = "WriteProcessMemory failed err=" + Marshal.GetLastWin32Error(); return false; }
        return true;
    }

    const int DBG_CONTINUE = 0x00010002;
    const int CONTEXT_FLAGS_OFF = 0x30;
    const int CONTEXT_EFlags_OFF = 0x44;
    const int CONTEXT_RCX_OFF = 0x80;
    const int CONTEXT_RDX_OFF = 0x88;
    const int CONTEXT_RSP_OFF = 0x98;
    const int CONTEXT_R8_OFF = 0xB8;
    const int CONTEXT_R9_OFF = 0xC0;
    const int CONTEXT_RIP_OFF = 0xF8;
    const uint CONTEXT_FULL = 0x0010000B;

    static StreamWriter log;
    static void L(string s) { log.WriteLine(DateTime.Now.ToString("HH:mm:ss.fff") + " " + s); log.Flush(); }

    static long GetTargetNtdllFunc(int pid, out IntPtr proc) {
        proc = OpenProcess(0x0438, false, pid);
        if (proc == IntPtr.Zero) return 0;
        IntPtr[] mods = new IntPtr[1024];
        int needed;
        if (!EnumProcessModulesEx(proc, mods, mods.Length * IntPtr.Size, out needed, 0x03)) return 0;
        long targetNtdll = 0;
        int count = needed / IntPtr.Size;
        for (int i = 0; i < count && i < 1024; i++) {
            StringBuilder sb = new StringBuilder(260);
            GetModuleBaseName(proc, mods[i], sb, 260);
            if (sb.ToString().ToLowerInvariant() == "ntdll.dll") { targetNtdll = (long)mods[i]; break; }
        }
        if (targetNtdll == 0) return 0;
        IntPtr myNtdll = GetModuleHandleA("ntdll.dll");
        IntPtr myFunc = GetProcAddress(myNtdll, "NtDeviceIoControlFile");
        if (myFunc == IntPtr.Zero) return 0;
        long offset = (long)myFunc - (long)myNtdll;
        return targetNtdll + offset;
    }

    static string HexDump(byte[] b, int off, int len) {
        var sb = new StringBuilder();
        for (int i = off; i < off + len && i < b.Length; i++) sb.Append(b[i].ToString("X2") + " ");
        return sb.ToString();
    }

    public static string Run(int pid, string from, string to, int maxHits, int runSeconds, string logFile) {
        log = new StreamWriter(logFile, false);
        var sb = new StringBuilder();
        try {
            IntPtr proc;
            long funcAddr = GetTargetNtdllFunc(pid, out proc);
            if (funcAddr == 0) { L("FAILED to locate ntdll!NtDeviceIoControlFile in target"); return "FAIL"; }
            L("target NtDeviceIoControlFile @ 0x" + funcAddr.ToString("X"));

            // save original byte, set 0xCC
            byte[] orig = new byte[1]; long got;
            ReadProcessMemory(proc, funcAddr, orig, 1, out got);
            string e1;
            if (!WriteCodeByte(proc, funcAddr, 0xCC, out e1)) { L("set bp FAILED: " + e1); return "FAIL"; }
            L("breakpoint set (orig byte 0x" + orig[0].ToString("X2") + ")");

            if (!DebugActiveProcess(pid)) { L("DebugActiveProcess failed err=" + Marshal.GetLastWin32Error()); string e0; WriteCodeByte(proc, funcAddr, orig[0], out e0); return "FAIL"; }
            DebugSetProcessKillOnExit(false);
            L("debugger attached");

            byte[] evt = new byte[256];
            int hits = 0;
            DateTime start = DateTime.Now;
            byte[] fromU = Encoding.Unicode.GetBytes(from);
            byte[] toU = Encoding.Unicode.GetBytes(to);
            byte[] fromA = Encoding.ASCII.GetBytes(from);
            byte[] toA = Encoding.ASCII.GetBytes(to);

            while ((DateTime.Now - start).TotalSeconds < runSeconds && hits < maxHits) {
                if (!WaitForDebugEvent(evt, 1000)) continue;
                int code = BitConverter.ToInt32(evt, 0);
                int epid = BitConverter.ToInt32(evt, 4);
                int tid = BitConverter.ToInt32(evt, 8);

                if (code == 1) { // EXCEPTION_DEBUG_EVENT
                    int excCode = BitConverter.ToInt32(evt, 12);
                    long excAddr = BitConverter.ToInt64(evt, 28);

                    if (excCode == unchecked((int)0x80000003) && excAddr == funcAddr) {
                        // breakpoint hit - get context
                        IntPtr ht = OpenThread(0x0008 | 0x0010 | 0x0020 /*GET|SET|SUSPEND? use 0x1FFFFF all*/, false, tid);
                        if (ht == IntPtr.Zero) ht = OpenThread(0x1FFFFF, false, tid);
                        IntPtr ctx = Marshal.AllocHGlobal(1232);
                        for (int i = 0; i < 1232; i++) Marshal.WriteByte(ctx, i, 0);
                        Marshal.WriteInt32(ctx, CONTEXT_FLAGS_OFF, unchecked((int)CONTEXT_FULL));
                        GetThreadContext(ht, ctx);

                        long rcx = Marshal.ReadInt64(ctx, CONTEXT_RCX_OFF);
                        long rsp = Marshal.ReadInt64(ctx, CONTEXT_RSP_OFF);
                        long r9 = Marshal.ReadInt64(ctx, CONTEXT_R9_OFF);
                        long ioStatus = 0, inBuf = 0, inLen = 0, outBuf = 0, outLen = 0, ioctl = 0;
                        byte[] p = new byte[8]; long g2;
                        ReadProcessMemory(proc, rsp + 0x28, p, 8, out g2); ioStatus = BitConverter.ToInt64(p, 0);
                        ReadProcessMemory(proc, rsp + 0x30, p, 8, out g2); inBuf = BitConverter.ToInt64(p, 0);
                        ReadProcessMemory(proc, rsp + 0x38, p, 8, out g2); inLen = BitConverter.ToInt64(p, 0);
                        ReadProcessMemory(proc, rsp + 0x40, p, 8, out g2); outBuf = BitConverter.ToInt64(p, 0);
                        ReadProcessMemory(proc, rsp + 0x48, p, 8, out g2); outLen = BitConverter.ToInt64(p, 0);
                        ReadProcessMemory(proc, rsp + 0x50, p, 8, out g2); ioctl = BitConverter.ToInt64(p, 0);

                        hits++;
                        L("=== IOCTL HIT #" + hits + " tid=" + tid + " handle=0x" + rcx.ToString("X") + " ioctl=0x" + ioctl.ToString("X") + " inBuf=0x" + inBuf.ToString("X") + " inLen=" + inLen + " outBuf=0x" + outBuf.ToString("X") + " outLen=" + outLen);

                        if (inBuf != 0 && inLen > 0) {
                            int readN = (int)Math.Min(inLen, 16384);
                            byte[] buf = new byte[readN]; long g3;
                            if (ReadProcessMemory(proc, inBuf, buf, readN, out g3)) {
                                L("  inbuf bytes: " + HexDump(buf, 0, Math.Min(readN, 128)));
                                // search utf16
                                int pos = -1;
                                for (int i = 0; i + fromU.Length <= readN; i++) {
                                    bool m = true;
                                    for (int j = 0; j < fromU.Length; j++) if (buf[i + j] != fromU[j]) { m = false; break; }
                                    if (m) { pos = i; break; }
                                }
                                int mode = 0;
                                if (pos < 0) {
                                    for (int i = 0; i + fromA.Length <= readN; i++) {
                                        bool m = true;
                                        for (int j = 0; j < fromA.Length; j++) if (buf[i + j] != fromA[j]) { m = false; break; }
                                        if (m) { pos = i; mode = 1; break; }
                                    }
                                }
                                if (pos >= 0) {
                                    byte[] repl = mode == 0 ? toU : toA;
                                    long w2;
                                    if (WriteProcessMemory(proc, inBuf + pos, repl, repl.Length, out w2)) {
                                        L("  PATCHED '" + from + "' -> '" + to + "' at inbuf+0x" + pos.ToString("X") + " (" + (mode == 0 ? "utf16" : "ascii") + ")");
                                    } else {
                                        L("  patch write FAILED err=" + Marshal.GetLastWin32Error());
                                    }
                                } else {
                                    L("  no version string found in input buffer (first " + readN + " bytes)");
                                }
                            } else L("  read input buffer failed");
                        }

                        // rewind RIP to bp address, set TF for single-step
                        long rip = Marshal.ReadInt64(ctx, CONTEXT_RIP_OFF);
                        Marshal.WriteInt64(ctx, CONTEXT_RIP_OFF, funcAddr);
                        int eflags = Marshal.ReadInt32(ctx, CONTEXT_EFlags_OFF);
                        Marshal.WriteInt32(ctx, CONTEXT_EFlags_OFF, eflags | 0x100);
                        SetThreadContext(ht, ctx);
                        Marshal.FreeHGlobal(ctx);
                        CloseHandle(ht);
                        ContinueDebugEvent(epid, tid, DBG_CONTINUE);
                        continue;
                    }

                    if (excCode == unchecked((int)0x80000004)) {
                        // single-step after our bp: re-arm breakpoint
                        string e2;
                        WriteCodeByte(proc, funcAddr, 0xCC, out e2);
                        IntPtr ht2 = OpenThread(0x1FFFFF, false, tid);
                        if (ht2 != IntPtr.Zero) {
                            IntPtr ctx2 = Marshal.AllocHGlobal(1232);
                            for (int i = 0; i < 1232; i++) Marshal.WriteByte(ctx2, i, 0);
                            Marshal.WriteInt32(ctx2, CONTEXT_FLAGS_OFF, unchecked((int)CONTEXT_FULL));
                            GetThreadContext(ht2, ctx2);
                            int ef2 = Marshal.ReadInt32(ctx2, CONTEXT_EFlags_OFF);
                            Marshal.WriteInt32(ctx2, CONTEXT_EFlags_OFF, ef2 & ~0x100);
                            SetThreadContext(ht2, ctx2);
                            Marshal.FreeHGlobal(ctx2);
                            CloseHandle(ht2);
                        }
                        ContinueDebugEvent(epid, tid, DBG_CONTINUE);
                        continue;
                    }

                    // other exception - pass through
                    ContinueDebugEvent(epid, tid, DBG_CONTINUE);
                    continue;
                }

                ContinueDebugEvent(epid, tid, DBG_CONTINUE);
            }

            // cleanup
            string e3;
            WriteCodeByte(proc, funcAddr, orig[0], out e3);
            DebugActiveProcessStop(pid);
            L("done. hits=" + hits + " (bp removed, detached)");
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

Write-Host ("interceptor start: pid=" + $TargetPid + " patch " + $PatchFrom + " -> " + $PatchTo)
$result = [IoctlHook]::Run($TargetPid, $PatchFrom, $PatchTo, $MaxHits, $RunSeconds, $LogFile)
Write-Host ("RESULT: " + $result)
