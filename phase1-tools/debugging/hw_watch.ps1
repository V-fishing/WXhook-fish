param(
    [int]$TargetPid = 27488,
    [long]$WatchAddr = 0x2AD41DA7E30,
    [int]$RunSeconds = 600,
    [string]$LogFile = "C:\Users\fish\ZCodeProject\watch_log.txt"
)

Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public class HwWatch {
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
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool VirtualQueryEx(IntPtr h, long addr, out MEMORY_BASIC_INFORMATION info, int len);
    [DllImport("kernel32.dll")] static extern bool VirtualQuery(long addr, out MEMORY_BASIC_INFORMATION info, int len);
    [DllImport("psapi.dll", SetLastError=true)] static extern bool EnumProcessModulesEx(IntPtr h, IntPtr[] mods, int cb, out int needed, int filter);
    [DllImport("psapi.dll", CharSet=CharSet.Unicode)] static extern int GetModuleFileNameEx(IntPtr h, IntPtr mod, StringBuilder name, int size);

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public long BaseAddress; public long AllocationBase; public int AllocationProtect; public int __a1;
        public long RegionSize; public int State; public int Protect; public int Type; public int __a2;
    }

    const int DBG_CONTINUE = 0x00010002;
    const int CTX_FLAGS = 0x30, CTX_EFLAGS = 0x44, CTX_DR0 = 0x48, CTX_DR6 = 0x68, CTX_DR7 = 0x70;
    const int CTX_RCX = 0x80, CTX_RDX = 0x88, CTX_R8 = 0xB8, CTX_R9 = 0xC0, CTX_RSP = 0x98, CTX_RIP = 0xF8;
    const uint CONTEXT_FULL = 0x0010001B; // FULL | DEBUG_REGISTERS

    static StreamWriter log;
    static long watchAddr;
    static IntPtr proc;
    static void L(string s) { log.WriteLine(DateTime.Now.ToString("HH:mm:ss.fff") + " " + s); log.Flush(); }

    static void SetWatchOnThread(int tid) {
        IntPtr ht = OpenThread(0x1FFFFF, false, tid);
        if (ht == IntPtr.Zero) return;
        IntPtr ctx = Marshal.AllocHGlobal(1232);
        for (int i = 0; i < 1232; i++) Marshal.WriteByte(ctx, i, 0);
        Marshal.WriteInt32(ctx, CTX_FLAGS, unchecked((int)CONTEXT_FULL));
        if (GetThreadContext(ht, ctx)) {
            Marshal.WriteInt64(ctx, CTX_DR0, watchAddr);
            // DR7: L0=1 (bit0), RW0=3 (bits 16-17: read/write), LEN0=0 (bits 18-19: 1 byte)
            ulong dr7 = 0;
            dr7 |= 1UL;                      // L0
            dr7 |= (3UL << 16);              // RW0 = read/write
            // LEN0 = 0 -> 1 byte
            Marshal.WriteInt64(ctx, CTX_DR7, (long)dr7);
            SetThreadContext(ht, ctx);
        }
        Marshal.FreeHGlobal(ctx);
        CloseHandle(ht);
    }

    static string ModuleOf(long addr) {
        try {
            IntPtr[] mods = new IntPtr[1024];
            int needed;
            if (!EnumProcessModulesEx(proc, mods, mods.Length * IntPtr.Size, out needed, 0x03)) return "?";
            int count = needed / IntPtr.Size;
            for (int i = 0; i < count && i < 1024; i++) {
                var mbi = new MEMORY_BASIC_INFORMATION();
                if (!VirtualQueryEx(proc, (long)mods[i], out mbi, Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)))) continue;
                long baseA = (long)mods[i];
                long endA = baseA + mbi.RegionSize;
                if (addr >= baseA && addr < endA) {
                    StringBuilder sb = new StringBuilder(300);
                    GetModuleFileNameEx(proc, mods[i], sb, 300);
                    string p = sb.ToString();
                    int idx = p.LastIndexOf('\\');
                    return (idx >= 0 ? p.Substring(idx + 1) : p) + "+0x" + (addr - baseA).ToString("X");
                }
            }
        } catch {}
        return "?";
    }

    public static string Run(int pid, long addr, int runSeconds, string logFile) {
        log = new StreamWriter(logFile, false);
        watchAddr = addr;
        try {
            proc = OpenProcess(0x0410, false, pid);
            if (proc == IntPtr.Zero) { L("OpenProcess failed"); return "FAIL"; }
            L("watching addr 0x" + addr.ToString("X") + " in pid " + pid);

            if (!DebugActiveProcess(pid)) { L("DebugActiveProcess failed err=" + Marshal.GetLastWin32Error()); return "FAIL"; }
            DebugSetProcessKillOnExit(false);
            L("debugger attached; setting hw breakpoints on existing threads");

            byte[] evt = new byte[256];
            int hits = 0;
            DateTime start = DateTime.Now;
            var seenThreads = new HashSet<int>();

            while ((DateTime.Now - start).TotalSeconds < runSeconds && hits < 60) {
                if (!WaitForDebugEvent(evt, 500)) continue;
                int code = BitConverter.ToInt32(evt, 0);
                int epid = BitConverter.ToInt32(evt, 4);
                int tid = BitConverter.ToInt32(evt, 8);

                if (code == 1) { // exception
                    int excCode = BitConverter.ToInt32(evt, 12);
                    if (excCode == unchecked((int)0x80000004)) {
                        // single step / hw breakpoint hit
                        IntPtr ht = OpenThread(0x1FFFFF, false, tid);
                        IntPtr ctx = Marshal.AllocHGlobal(1232);
                        for (int i = 0; i < 1232; i++) Marshal.WriteByte(ctx, i, 0);
                        Marshal.WriteInt32(ctx, CTX_FLAGS, unchecked((int)CONTEXT_FULL));
                        GetThreadContext(ht, ctx);
                        long dr6 = Marshal.ReadInt64(ctx, CTX_DR6);
                        if ((dr6 & 0xF) != 0) {
                            hits++;
                            long rip = Marshal.ReadInt64(ctx, CTX_RIP);
                            long rcx = Marshal.ReadInt64(ctx, CTX_RCX);
                            long rdx = Marshal.ReadInt64(ctx, CTX_RDX);
                            long r8 = Marshal.ReadInt64(ctx, CTX_R8);
                            long rsp = Marshal.ReadInt64(ctx, CTX_RSP);
                            string mod = ModuleOf(rip);
                            L("HW-BP HIT #" + hits + " tid=" + tid + " rip=0x" + rip.ToString("X") + " (" + mod + ") dr6=0x" + dr6.ToString("X") + " rcx=0x" + rcx.ToString("X") + " rdx=0x" + rdx.ToString("X") + " r8=0x" + r8.ToString("X"));
                            // dump code bytes at rip
                            byte[] codeb = new byte[48]; long got;
                            if (ReadProcessMemory(proc, rip, codeb, 48, out got)) {
                                var sb = new StringBuilder();
                                foreach (byte b in codeb) sb.Append(b.ToString("X2") + " ");
                                L("   code@rip: " + sb.ToString());
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

                if (code == 2) { // CREATE_THREAD_DEBUG_EVENT
                    // thread info: hThread at offset 12 (8 bytes)
                    long hThread = BitConverter.ToInt64(evt, 12);
                    SetWatchOnThread(tid);
                    L("new thread " + tid + " (hw bp set)");
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

Write-Host ("hw watch: pid=" + $TargetPid + " addr=0x" + $WatchAddr.ToString("X"))
$result = [HwWatch]::Run($TargetPid, $WatchAddr, $RunSeconds, $LogFile)
Write-Host ("RESULT: " + $result)
