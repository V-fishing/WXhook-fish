param(
    [int]$TargetPid = 9936,
    [long]$Addr1 = 0x21815D87840,
    [long]$Addr2 = 0x2181AD60000,
    [int]$RunSeconds = 240,
    [string]$LogFile = "C:\Users\fish\ZCodeProject\tool_watch.txt"
)

Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public class ToolWatch {
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

    const int DBG_CONTINUE = 0x00010002;
    const int CTX_FLAGS = 0x30, CTX_DR0 = 0x48, CTX_DR1 = 0x50, CTX_DR6 = 0x68, CTX_DR7 = 0x70;
    const int CTX_RCX = 0x80, CTX_RDX = 0x88, CTX_R8 = 0xB8, CTX_RSP = 0x98, CTX_RIP = 0xF8;
    const uint CONTEXT_FULL = 0x0010001B;

    static StreamWriter log;
    static long a1, a2;
    static IntPtr proc;
    static void L(string s) { log.WriteLine(DateTime.Now.ToString("HH:mm:ss.fff") + " " + s); log.Flush(); }

    static void SetWatch(int tid) {
        IntPtr ht = OpenThread(0x1FFFFF, false, tid);
        if (ht == IntPtr.Zero) return;
        IntPtr ctx = Marshal.AllocHGlobal(1232);
        for (int i = 0; i < 1232; i++) Marshal.WriteByte(ctx, i, 0);
        Marshal.WriteInt32(ctx, CTX_FLAGS, unchecked((int)CONTEXT_FULL));
        if (GetThreadContext(ht, ctx)) {
            Marshal.WriteInt64(ctx, CTX_DR0, a1);
            Marshal.WriteInt64(ctx, CTX_DR1, a2);
            ulong dr7 = 0;
            dr7 |= 1UL; dr7 |= (3UL << 16);
            dr7 |= (1UL << 2); dr7 |= (3UL << 20);
            Marshal.WriteInt64(ctx, CTX_DR7, (long)dr7);
            SetThreadContext(ht, ctx);
        }
        Marshal.FreeHGlobal(ctx);
        CloseHandle(ht);
    }

    public static string Run(int pid, long addr1, long addr2, int runSeconds, string logFile) {
        log = new StreamWriter(logFile, false);
        a1 = addr1; a2 = addr2;
        try {
            proc = OpenProcess(0x0410, false, pid);
            if (proc == IntPtr.Zero) { L("OpenProcess failed"); return "FAIL"; }
            if (!DebugActiveProcess(pid)) { L("DebugActiveProcess failed err=" + Marshal.GetLastWin32Error()); return "FAIL"; }
            DebugSetProcessKillOnExit(false);
            L("attached; watching 0x" + addr1.ToString("X") + " and 0x" + addr2.ToString("X"));

            byte[] evt = new byte[256];
            int hits = 0;
            DateTime start = DateTime.Now;
            while ((DateTime.Now - start).TotalSeconds < runSeconds && hits < 40) {
                if (!WaitForDebugEvent(evt, 500)) continue;
                int code = BitConverter.ToInt32(evt, 0);
                int epid = BitConverter.ToInt32(evt, 4);
                int tid = BitConverter.ToInt32(evt, 8);

                if (code == 2) { SetWatch(tid); L("thread " + tid + " armed"); }
                else if (code == 1) {
                    int excCode = BitConverter.ToInt32(evt, 12);
                    if (excCode == unchecked((int)0x80000004)) {
                        IntPtr ht = OpenThread(0x1FFFFF, false, tid);
                        IntPtr ctx = Marshal.AllocHGlobal(1232);
                        for (int i = 0; i < 1232; i++) Marshal.WriteByte(ctx, i, 0);
                        Marshal.WriteInt32(ctx, CTX_FLAGS, unchecked((int)CONTEXT_FULL));
                        GetThreadContext(ht, ctx);
                        long dr6 = Marshal.ReadInt64(ctx, CTX_DR6);
                        if ((dr6 & 0xF) != 0) {
                            hits++;
                            long rip = Marshal.ReadInt64(ctx, CTX_RIP);
                            string which = ((dr6 & 1) != 0 ? "ADDR1(剩余次数)" : "") + ((dr6 & 2) != 0 ? " ADDR2(机器编码)" : "");
                            L("HIT #" + hits + " [" + which.Trim() + "] tid=" + tid + " rip=0x" + rip.ToString("X"));
                            byte[] codeb = new byte[48]; long got;
                            if (ReadProcessMemory(proc, rip - 16, codeb, 48, out got)) {
                                var sb = new StringBuilder();
                                foreach (byte b in codeb) sb.Append(b.ToString("X2") + " ");
                                L("   code(rip-16): " + sb.ToString());
                            }
                        }
                        Marshal.FreeHGlobal(ctx);
                        CloseHandle(ht);
                        ContinueDebugEvent(epid, tid, DBG_CONTINUE);
                        continue;
                    }
                    ContinueDebugEvent(epid, tid, DBG_CONTINUE);
                    continue;
                }
                ContinueDebugEvent(epid, tid, DBG_CONTINUE);
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

Write-Host ("tool-watch: pid=" + $TargetPid)
$result = [ToolWatch]::Run($TargetPid, $Addr1, $Addr2, $RunSeconds, $LogFile)
Write-Host ("RESULT: " + $result)
