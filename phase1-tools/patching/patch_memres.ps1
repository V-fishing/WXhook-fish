param(
    [int]$ProcId = 27488,
    [long]$DllBase = 0x7FF8ACA40000
)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public class MemRes {
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadProcessMemory(IntPtr h, long addr, byte[] buf, long size, out long read);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool WriteProcessMemory(IntPtr h, long addr, byte[] buf, long size, out long written);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool VirtualProtectEx(IntPtr h, long addr, long size, int newProtect, out int oldProtect);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);

    public static string Go(int pid, long baseAddr) {
        IntPtr h = OpenProcess(0x0438, false, pid);
        if (h == IntPtr.Zero) return "OpenProcess failed err=" + Marshal.GetLastWin32Error();
        var sb = new StringBuilder();

        long fixedInfo = baseAddr + 0x41D50C8;
        long nodeHdr = baseAddr + 0x41D51A0;
        long strAddr = baseAddr + 0x41D51C0;

        // 1. read current string
        byte[] before = new byte[24]; long got;
        ReadProcessMemory(h, strAddr, before, 24, out got);
        sb.AppendLine("string before: '" + Encoding.Unicode.GetString(before).Split((char)0)[0] + "'");

        // 2. unprotect the page (make RW)
        int oldProt;
        bool vp = VirtualProtectEx(h, strAddr & ~0xFFF, 0x1000, 0x04, out oldProt);
        sb.AppendLine("VirtualProtectEx: ok=" + vp + " err=" + Marshal.GetLastWin32Error() + " oldProt=0x" + oldProt.ToString("X"));

        // 3. write new string: "4.1.13.65" + null (20 bytes)
        byte[] nb = Encoding.Unicode.GetBytes("4.1.13.65");
        byte[] payload = new byte[nb.Length + 2];
        Array.Copy(nb, payload, nb.Length);
        long w;
        bool ok1 = WriteProcessMemory(h, strAddr, payload, payload.Length, out w);
        sb.AppendLine("write string: ok=" + ok1 + " err=" + Marshal.GetLastWin32Error());

        // 4. fix node wValueLength 9 -> 10 (offset +2 in node header)
        byte[] vlen = new byte[] { 10, 0 };
        bool ok2 = WriteProcessMemory(h, nodeHdr + 2, vlen, 2, out w);
        sb.AppendLine("write wValueLength=10: ok=" + ok2);

        // 5. fixedinfo file version: MS=4.1, LS=13.65
        byte[] fi = new byte[] { 0x01, 0x00, 0x04, 0x00, 0x41, 0x00, 0x0D, 0x00 };
        bool ok3 = WriteProcessMemory(h, fixedInfo + 8, fi, 8, out w);
        sb.AppendLine("write fixedinfo file version: ok=" + ok3);

        // 6. restore protection
        int dummy;
        VirtualProtectEx(h, strAddr & ~0xFFF, 0x1000, oldProt, out dummy);

        // 7. verify
        byte[] after = new byte[24];
        ReadProcessMemory(h, strAddr, after, 24, out got);
        sb.AppendLine("string after:  '" + Encoding.Unicode.GetString(after).Split((char)0)[0] + "'");
        byte[] chk = new byte[12];
        ReadProcessMemory(h, fixedInfo + 4, chk, 12, out got);
        sb.AppendLine("fixedinfo after: " + BitConverter.ToString(chk));
        CloseHandle(h);
        return sb.ToString();
    }
}
"@

Write-Host ([MemRes]::Go($ProcId, $DllBase))
