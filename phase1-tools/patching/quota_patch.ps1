param(
    [int]$ProcId = 1716,
    [long]$QuotaAddr = 0x1E3D8C2B790
)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public class QuotaPatch {
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadProcessMemory(IntPtr h, long addr, byte[] buf, long size, out long read);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool WriteProcessMemory(IntPtr h, long addr, byte[] buf, long size, out long written);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);

    public static string Go(int pid, long addr) {
        IntPtr h = OpenProcess(0x0438, false, pid);
        if (h == IntPtr.Zero) return "OpenProcess failed err=" + Marshal.GetLastWin32Error();
        byte[] before = new byte[32]; long got;
        ReadProcessMemory(h, addr, before, 32, out got);
        string b4 = Encoding.Unicode.GetString(before).Split((char)0)[0];
        byte[] nine = new byte[] { 0x39, 0x00 };
        long w;
        bool ok = WriteProcessMemory(h, addr + 14, nine, 2, out w);
        byte[] after = new byte[32];
        ReadProcessMemory(h, addr, after, 32, out got);
        string af = Encoding.Unicode.GetString(after).Split((char)0)[0];
        CloseHandle(h);
        return "before: '" + b4 + "' | write ok=" + ok + " | after: '" + af + "'";
    }
}
"@

Write-Host ([QuotaPatch]::Go($ProcId, $QuotaAddr))
