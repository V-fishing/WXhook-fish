param(
    [int]$ProcId = 27808,
    [long]$StringAddr = 0x1CDF2B47E30,
    [long]$HeapIntAddr = 0x1CD80C70024
)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class Diag {
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadProcessMemory(IntPtr h, long addr, byte[] buf, long size, out long read);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool WriteProcessMemory(IntPtr h, long addr, byte[] buf, long size, out long written);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool VirtualProtectEx(IntPtr h, long addr, long size, int newProtect, out int oldProtect);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool VirtualAllocEx(IntPtr h, long addr, long size, int type, int protect);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool VirtualFreeEx(IntPtr h, long addr, long size, int type);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr h);

    public static string Run(int pid, long stringAddr, long heapAddr) {
        IntPtr h = OpenProcess(0x0438, false, pid);
        if (h == IntPtr.Zero) return "OpenProcess(0x438) FAILED err=" + Marshal.GetLastWin32Error();
        var sb = new System.Text.StringBuilder();

        // 1. no-op write of the SAME 4 bytes at a heap int location (should be writable)
        byte[] cur = new byte[4]; long got;
        ReadProcessMemory(h, heapAddr, cur, 4, out got);
        long w;
        bool ok = WriteProcessMemory(h, heapAddr, cur, 4, out w);
        sb.AppendLine("1. write writable-heap-page @0x" + heapAddr.ToString("X") + " (no-op): ok=" + ok + " err=" + Marshal.GetLastWin32Error());

        // 2. VirtualProtectEx on the writable heap page (to RW, then restore to RW - harmless)
        int oldP;
        bool vp1 = VirtualProtectEx(h, heapAddr, 4, 0x04, out oldP);
        sb.AppendLine("2. VirtualProtectEx on heap page: ok=" + vp1 + " err=" + Marshal.GetLastWin32Error() + " oldProt=0x" + oldP.ToString("X"));

        // 3. VirtualProtectEx on the read-only string page
        int oldP2;
        bool vp2 = VirtualProtectEx(h, stringAddr, 20, 0x04, out oldP2);
        sb.AppendLine("3. VirtualProtectEx on string page (RO->RW): ok=" + vp2 + " err=" + Marshal.GetLastWin32Error() + " oldProt=0x" + oldP2.ToString("X"));

        // 4. if step 3 succeeded, try the write now
        if (vp2) {
            byte[] patch = System.Text.Encoding.Unicode.GetBytes("4.1.13.65");
            byte[] payload = new byte[patch.Length + 2];
            Array.Copy(patch, payload, patch.Length);
            ok = WriteProcessMemory(h, stringAddr, payload, payload.Length, out w);
            sb.AppendLine("4. write string page after unprotect: ok=" + ok + " err=" + Marshal.GetLastWin32Error() + " written=" + w);
            int tmp;
            VirtualProtectEx(h, stringAddr, 20, oldP2, out tmp);
        }

        // 5. VirtualAllocEx test (VM_OPERATION check)
        bool va = VirtualAllocEx(h, 0, 4096, 0x1000 /*MEM_COMMIT*/, 0x04 /*RW*/);
        int vaErr = Marshal.GetLastWin32Error();
        sb.AppendLine("5. VirtualAllocEx (VM_OPERATION test): ok=" + va + " err=" + vaErr);

        CloseHandle(h);
        return sb.ToString();
    }
}
"@

Write-Host ([Diag]::Run($ProcId, $StringAddr, $HeapIntAddr))
Write-Host ("string now: '" + (powershell -NoProfile -Command "exit 0") + "' 2>`$null")
# re-read string
$after = powershell -NoProfile -ExecutionPolicy Bypass -Command "& 'C:\Users\fish\ZCodeProject\dump_wx_version.ps1' -ProcId $ProcId -Addresses @($StringAddr)" 2>&1 | Select-String "version string" -Context 0,0
$after | Select-Object -First 1 | ForEach-Object { $_.Line }