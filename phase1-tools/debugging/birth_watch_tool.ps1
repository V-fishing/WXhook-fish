param(
    [string]$ProcName = "WeChat.exe",
    [int]$RunSeconds = 600,
    [string]$LogFile = "C:\Users\fish\ZCodeProject\birth_watch_log.txt"
)

Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

public class BirthWatchTool {
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
    [DllImport("kernel32.dll", SetLastError=true)] static extern long VirtualQueryEx(IntPtr h, long addr, out MEMORY_BASIC_INFORMATION info, int len);
    [DllImport("psapi.dll", SetLastError=true)] static extern bool EnumProcessModulesEx(IntPtr h, IntPtr[] mods, int cb, out int needed, int filter);
    [DllImport("psapi.dll", CharSet=CharSet.Unicode)] static extern int GetModuleFileNameEx(IntPtr h, IntPtr mod, StringBuilder name, int size);

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public long BaseAddress; public long AllocationBase; public int AllocationProtect; public int __a1;
        public long RegionSize; public int State; public int Protect; public int Type; public int __a2;
    }

    const int DBG_CONTINUE = 0x00010002;
    const int CTX_FLAGS = 0x30, CTX_DR0 = 0x48, CTX_DR1 = 0x50, CTX_DR6 = 0x68, CTX_DR7 = 0x70;
    const int CTX_RCX = 0x80, CTX_RDX = 0x88, CTX_R8 = 0xB8, CTX_RSP = 0x98, CTX_RIP = 0xF8;
    const uint CONTEXT_FULL = 0x0010001B;

    static StreamWriter log;
    static long blobAddr = 0, intAddr = 0;
    static IntPtr proc;
    static void L(string s) { log.WriteLine(DateTime.Now.ToString("HH:mm:ss.fff") + " " + s); log.Flush(); }

    // scan process memory for utf16 string, return address or 0
    static long FindString(IntPtr h, byte[] pat) {
        long addr = 0;
        var mbi = new MEMORY_BASIC_INFORMATION();
        byte[] buf = new byte[1 << 20];
        while (addr < 0x7FFFFFFFFFFF) {
            long q = VirtualQueryEx(h, addr, out mbi, Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
            if (q == 0) break;
            bool readable = mbi.State == 0x1000 && (mbi.Protect & 0x100) == 0 && mbi.Protect != 0x01 && mbi.Protect != 0x00;
            if (readable && mbi.RegionSize <= (64L << 20)) {
                long off = 0;
                while (off < mbi.RegionSize) {
                    long chunk = Math.Min(buf.Length, mbi.RegionSize - off);
                    long got;
                    if (ReadProcessMemory(h, mbi.BaseAddress + off, buf, chunk, out got) && got >= pat.Length) {
                        for (int i = 0; i + pat.Length <= got; i++) {
                            bool m = true;
                            for (int j = 0; j < pat.Length; j++) if (buf[i + j] != pat[j]) { m = false; break; }
                            if (m) return mbi.BaseAddress + off + i;
                        }
                    }
                    off += chunk;
                }
            }
            addr = mbi.BaseAddress + mbi.RegionSize;
        }
        return 0;
    }

    static void SetWatch(int tid) {
        IntPtr ht = OpenThread(0x1FFFFF, false, tid);
        if (ht == IntPtr.Zero) return;
        IntPtr ctx = Marshal.AllocHGlobal(1232);
        for (int i = 0; i < 1232; i++) Marshal.WriteByte(ctx, i, 0);
        Marshal.WriteInt32(ctx, CTX_FLAGS, unchecked((int)CONTEXT_FULL));
        if (GetThreadContext(ht, ctx)) {
            Marshal.WriteInt64(ctx, CTX_DR0, blobAddr);
            Marshal.WriteInt64(ctx, CTX_DR1, intAddr);
            ulong dr7 = 0;
            dr7 |= 1UL; dr7 |= (3UL << 16);            // DR0: read/write, 1 byte
            dr7 |= (1UL << 2); dr7 |= (3UL << 20);     // DR1: read/write, 1 byte
            Marshal.WriteInt64(ctx, CTX_DR7, (long)dr7);
            SetThreadContext(ht, ctx);
        }
        Marshal.FreeHGlobal(ctx);
        CloseHandle(ht);
    }

    public static string Run(string procName, int runSeconds, string logFile) {
        log = new StreamWriter(logFile, false);
        try {
            L("waiting for new " + procName + " process...");
            int pid = 0;
            DateTime t0 = DateTime.Now;
            while ((DateTime.Now - t0).TotalSeconds < 120) {
                Process newest = null;
                foreach (var p in Process.GetProcessesByName(procName.Replace(".exe", ""))) {
                    try {
                        if (newest == null || p.StartTime > newest.StartTime) newest = p;
                    } catch {}
                }
                if (newest != null) {
                    try {
                        double age = (DateTime.Now - newest.StartTime).TotalSeconds;
                        if (age < 30) { pid = newest.Id; break; }  // fresh process
                    } catch {}
                }
                System.Threading.Thread.Sleep(150);
            }
            if (pid == 0) { L("no fresh process found"); return "FAIL"; }
            L("found fresh pid " + pid);

            proc = OpenProcess(0x0410, false, pid);
            if (proc == IntPtr.Zero) { L("OpenProcess failed"); return "FAIL"; }

            byte[] blobPat = Encoding.Unicode.GetBytes("剩余次数");
            byte[] intPat = Encoding.Unicode.GetBytes("机器编码"); // different anchor
            byte[] intPatOld = Encoding.Unicode.GetBytes("剩余次数: 0");
            DateTime ts = DateTime.Now;
            while ((DateTime.Now - ts).TotalSeconds < 60) {
                blobAddr = FindString(proc, blobPat);
                if (blobAddr != 0) break;
                System.Threading.Thread.Sleep(300);
            }
            L("blob string @ 0x" + blobAddr.ToString("X"));
            // int global: find either the new or old pattern; prefer the one near the DLL
            while ((DateTime.Now - ts).TotalSeconds < 90) {
                intAddr = FindString(proc, intPat);
                if (intAddr == 0) intAddr = FindString(proc, intPatOld);
                if (intAddr != 0) break;
                System.Threading.Thread.Sleep(300);
            }
            L("int global @ 0x" + intAddr.ToString("X"));

            if (!DebugActiveProcess(pid)) { L("DebugActiveProcess failed err=" + Marshal.GetLastWin32Error()); return "FAIL"; }
            DebugSetProcessKillOnExit(false);
            L("debugger attached (early!)");

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
                            string which = ((dr6 & 1) != 0 ? "BLOB-STRING" : "") + ((dr6 & 2) != 0 ? " INT-GLOBAL" : "");
                            L("HIT #" + hits + " [" + which.Trim() + "] tid=" + tid + " rip=0x" + rip.ToString("X"));
                            byte[] codeb = new byte[32]; long got;
                            if (ReadProcessMemory(proc, rip, codeb, 32, out got)) {
                                var sb = new StringBuilder();
                                foreach (byte b in codeb) sb.Append(b.ToString("X2") + " ");
                                L("   code: " + sb.ToString());
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

Write-Host ("birth-watch starting for " + $ProcName)
$result = [BirthWatchTool]::Run($ProcName, $RunSeconds, $LogFile)
Write-Host ("RESULT: " + $result)
