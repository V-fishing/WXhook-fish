param(
    [int]$ProcId = 11180,
    [long]$ModuleBase = 0,
    [long[]]$Offsets = @(0x3A70FD4, 0x3A878DC, 0x3AA0508, 0x3AC85F0, 0x3ACF3D8, 0x3AD1908)
)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class ReadInts {
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll")] static extern bool ReadProcessMemory(IntPtr h, long addr, byte[] buf, long size, out long read);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    public static uint[] Go(int pid, long baseAddr, long[] offs) {
        IntPtr h = OpenProcess(0x0410, false, pid);
        if (h == IntPtr.Zero) return null;
        uint[] res = new uint[offs.Length];
        for (int i = 0; i < offs.Length; i++) {
            byte[] b = new byte[4]; long got;
            if (ReadProcessMemory(h, baseAddr + offs[i], b, 4, out got)) res[i] = BitConverter.ToUInt32(b, 0);
            else res[i] = 0xFFFFFFFF;
        }
        CloseHandle(h);
        return res;
    }
}
"@

if ($ModuleBase -eq 0) {
    $ModuleBase = [long](Get-Process -Id $ProcId -Module | Where-Object { $_.ModuleName -eq 'WeChatWin.dll' }).BaseAddress
}
Write-Host ("WeChatWin.dll base = 0x" + $ModuleBase.ToString("X"))
$vals = [ReadInts]::Go($ProcId, $ModuleBase, $Offsets)
for ($i = 0; $i -lt $Offsets.Count; $i++) {
    Write-Host ("  +0x{0:X}: 0x{1:X8}" -f $Offsets[$i], $vals[$i])
}
