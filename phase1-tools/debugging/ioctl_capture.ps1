param(
    [int]$TargetPid = 9936,
    [int]$RunSeconds = 240,
    [string]$LogFile = "C:\Users\fish\ZCodeProject\ioctl_capture.txt"
)

Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public class IoCapture {
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
    const int CTX_FLAGS = 0x30, CTX_EFLAGS = 0x44, CTX_RCX = 0x80, CTX_RSP = 0x98, CTX_RIP = 0xF8;
    const uint CONTEXT_FULL = 0x0010000B;

    static StreamWriter log;
    static IntPtr proc;
    static long funcAddr, ntdllBase, ntdllEnd;
    static long pendingRet = 0;          // return-address bp site
    static long pendingOutBuf = 0;
    static long pendingOutLen = 0;
    static long lastRestored = 0;        // address whose byte we restored (needs rearm after TF)
    static Dictionary<long, byte> origBytes = new Dictionary<long, byte>();

    static void L(string s) { log.WriteLine(DateTime.Now.ToString("HH:mm:ss.fff") + " " + s); log.Flush(); }

    static bool WriteCodeByte(long addr, byte val) {
        int oldProt;
        if (!VirtualProtectEx(proc, addr, 16, 0x40, out oldProt)) return false;
        byte[] b = new byte[] { val }; long w;
        bool ok = WriteProcessMemory(proc, addr, b, 1, out w);
        int d;
        VirtualProtectEx(proc, addr, 16, oldProt, out d);
        return ok;
    }

    static string HexDump(byte[] b, int len) {
        var sb = new StringBuilder();
        for (int i = 0; i < len && i < b.Length; i++) sb.Append(b[i].ToString("X2") + " ");
        return sb.ToString();
    }

    public static string Run(int pid, int runSeconds, string logFile) {
        log = new StreamWriter(logFile, false);
        try {
            proc = OpenProcess(0x0438, false, pid);
            if (proc == IntPtr.Zero) { L("OpenProcess failed"); return "FAIL"; }

            // resolve ntdll!NtDeviceIoControlFile in target
            IntPtr[] mods = new IntPtr[1024];
            int needed;
            EnumProcessModulesEx(proc, mods, mods.Length * IntPtr.Size, out needed, 0x03);
            long targetNtdll = 0;
            int count = needed / IntPtr.Size;
            for (int i = 0; i < count && i < 1024; i++) {
                StringBuilder sb = new StringBuilder(260);
                GetModuleBaseName(proc, mods[i], sb, 260);
                if (sb.ToString().ToLowerInvariant() == "ntdll.dll") { targetNtdll = (long)mods[i]; break; }
            }
            if (targetNtdll == 0) { L("no ntdll"); return "FAIL"; }
            ntdllBase = targetNtdll;
            ntdllEnd = targetNtdll + 0x300000;
            IntPtr myNtdll = GetModuleHandleA("ntdll.dll");
            long off = (long)GetProcAddress(myNtdll, "NtDeviceIoControlFile") - (long)myNtdll;
            funcAddr = targetNtdll + off;
            L("NtDeviceIoControlFile @ 0x" + funcAddr.ToString("X"));

            byte[] orig = new byte[1]; long got;
            ReadProcessMemory(proc, funcAddr, orig, 1, out got);
            origBytes[funcAddr] = orig[0];
            if (!WriteCodeByte(funcAddr, 0xCC)) { L("bp set failed"); return "FAIL"; }

            if (!DebugActiveProcess(pid)) { L("attach failed"); return "FAIL"; }
            DebugSetProcessKillOnExit(false);
            L("attached; waiting for IOCTLs...");

            byte[] evt = new byte[256];
            int hits = 0;
            DateTime start = DateTime.Now;
            while ((DateTime.Now - start).TotalSeconds < runSeconds && hits < 200) {
                if (!WaitForDebugEvent(evt, 500)) continue;
                int code = BitConverter.ToInt32(evt, 0);
                int epid = BitConverter.ToInt32(evt, 4);
                int tid = BitConverter.ToInt32(evt, 8);

                if (code != 1) { ContinueDebugEvent(epid, tid, DBG_CONTINUE); continue; }
                int excCode = BitConverter.ToInt32(evt, 12);
                long excAddr = BitConverter.ToInt64(evt, 28);

                if (excCode == unchecked((int)0x80000003)) {
                    IntPtr ht = OpenThread(0x1FFFFF, false, tid);
                    IntPtr ctx = Marshal.AllocHGlobal(1232);
                    for (int i = 0; i < 1232; i++) Marshal.WriteByte(ctx, i, 0);
                    Marshal.WriteInt32(ctx, CTX_FLAGS, unchecked((int)CONTEXT_FULL));
                    GetThreadContext(ht, ctx);
                    long rsp = Marshal.ReadInt64(ctx, CTX_RSP);

                    if (excAddr == funcAddr) {
                        // ENTRY hit
                        byte[] a = new byte[8]; long g;
                        ReadProcessMemory(proc, rsp + 0x30, a, 8, out g); long inBuf = BitConverter.ToInt64(a, 0);
                        ReadProcessMemory(proc, rsp + 0x38, a, 8, out g); long inLen = BitConverter.ToInt64(a, 0);
                        ReadProcessMemory(proc, rsp + 0x40, a, 8, out g); long outBuf = BitConverter.ToInt64(a, 0);
                        ReadProcessMemory(proc, rsp + 0x48, a, 8, out g); long outLen = BitConverter.ToInt64(a, 0);
                        ReadProcessMemory(proc, rsp + 0x50, a, 8, out g); long ioctlCode = BitConverter.ToInt64(a, 0);
                        ReadProcessMemory(proc, rsp, a, 8, out g); long retAddr = BitConverter.ToInt64(a, 0);

                        hits++;
                        L("ENTRY #" + hits + " tid=" + tid + " ioctl=0x" + ioctlCode.ToString("X") + " inBuf=0x" + inBuf.ToString("X") + " inLen=" + inLen + " outBuf=0x" + outBuf.ToString("X") + " outLen=" + outLen + " ret=0x" + retAddr.ToString("X"));
                        if (inBuf != 0 && inLen > 0 && inLen < 65536) {
                            byte[] ib = new byte[(int)Math.Min(inLen, 256)]; long g2;
                            if (ReadProcessMemory(proc, inBuf, ib, ib.Length, out g2))
                                L("   in:  " + HexDump(ib, ib.Length));
                        }
                        // set return-address bp if the caller is the tool (not ntdll)
                        if (retAddr > 0x10000 && (retAddr < ntdllBase || retAddr > ntdllEnd)) {
                            pendingRet = retAddr;
                            pendingOutBuf = outBuf;
                            pendingOutLen = outLen;
                            if (!origBytes.ContainsKey(retAddr)) {
                                byte[] ob = new byte[1]; long g3;
                                ReadProcessMemory(proc, retAddr, ob, 1, out g3);
                                origBytes[retAddr] = ob[0];
                                WriteCodeByte(retAddr, 0xCC);
                            }
                        }
                    } else if (excAddr == pendingRet && pendingRet != 0) {
                        // RETURN hit -> dump output buffer (the response!)
                        L("RETURN tid=" + tid + " ret=0x" + excAddr.ToString("X"));
                        if (pendingOutBuf != 0 && pendingOutLen > 0 && pendingOutLen < 65536) {
                            byte[] ob = new byte[(int)Math.Min(pendingOutLen, 512)]; long g4;
                            if (ReadProcessMemory(proc, pendingOutBuf, ob, ob.Length, out g4))
                                L("   out: " + HexDump(ob, ob.Length));
                        }
                        pendingRet = 0;
                    }

                    // restore + rewind + TF
                    byte b = origBytes.ContainsKey(excAddr) ? origBytes[excAddr] : (byte)0x0F;
                    WriteCodeByte(excAddr, b);
                    lastRestored = excAddr;
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
                    if (lastRestored != 0) {
                        WriteCodeByte(lastRestored, 0xCC);
                        lastRestored = 0;
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
            }

            // cleanup: restore all original bytes
            foreach (var kv in origBytes) WriteCodeByte(kv.Key, kv.Value);
            DebugActiveProcessStop(pid);
            L("done. entry-hits=" + hits);
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

Write-Host ("ioctl capture: pid=" + $TargetPid)
$result = [IoCapture]::Run($TargetPid, $RunSeconds, $LogFile)
Write-Host ("RESULT: " + $result)
