param(
    [int]$ProcId = 23428,
    [long]$QuotaAddr = 0x13ECA2400C0,
    [long]$TargetAddr = 0x13ECC4A2055
)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class W2 {
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadProcessMemory(IntPtr h, long addr, byte[] buf, long size, out long read);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool WriteProcessMemory(IntPtr h, long addr, byte[] buf, long size, out long written);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);

    public static string Go(int pid, long quotaAddr, long targetAddr) {
        IntPtr h = OpenProcess(0x0438, false, pid);
        if (h == IntPtr.Zero) return "OpenProcess failed err=" + Marshal.GetLastWin32Error();
        string res = "";

        // 1. patch quota text '0' -> '9'  (string starts 16 bytes before the digit group)
        byte[] before = new byte[32]; long got;
        ReadProcessMemory(h, quotaAddr, before, 32, out got);
        res += "quota before: '" + System.Text.Encoding.Unicode.GetString(before).Split((char)0)[0] + "'\n";
        // "剩余次数: 0" = 5 chars + ": " + "0" => the '0' is at char index 7 => byte offset 14
        byte[] nine = new byte[] { 0x39, 0x00 };
        long w;
        WriteProcessMemory(h, quotaAddr + 14, nine, 2, out w);
        byte[] after = new byte[32];
        ReadProcessMemory(h, quotaAddr, after, 32, out got);
        res += "quota after:  '" + System.Text.Encoding.Unicode.GetString(after).Split((char)0)[0] + "'\n";

        // 2. patch ascii target string "3.9.11.17" -> "4.1.13.65"
        byte[] tb = new byte[16];
        ReadProcessMemory(h, targetAddr, tb, 16, out got);
        res += "target before: '" + System.Text.Encoding.ASCII.GetString(tb).Split((char)0)[0] + "'\n";
        byte[] nb = System.Text.Encoding.ASCII.GetBytes("4.1.13.65");
        WriteProcessMemory(h, targetAddr, nb, nb.Length, out w);
        byte[] ta = new byte[16];
        ReadProcessMemory(h, targetAddr, ta, 16, out got);
        res += "target after:  '" + System.Text.Encoding.ASCII.GetString(ta).Split((char)0)[0] + "'\n";

        CloseHandle(h);
        return res;
    }
}
"@

Write-Host ([W2]::Go($ProcId, $QuotaAddr, $TargetAddr))
