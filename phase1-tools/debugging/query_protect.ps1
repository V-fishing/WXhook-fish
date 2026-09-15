param(
    [int]$ProcId = 27808,
    [long]$Address = 0x1CDF2B47E30,
    [string]$NewVersion = "4.1.13.65",
    [switch]$Apply
)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class MemPatch {
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll")] static extern bool ReadProcessMemory(IntPtr h, long addr, byte[] buf, long size, out long read);
    [DllImport("kernel32.dll")] static extern bool WriteProcessMemory(IntPtr h, long addr, byte[] buf, long size, out long written);
    [DllImport("kernel32.dll")] static extern bool VirtualProtectEx(IntPtr h, long addr, long size, int newProtect, out int oldProtect);
    [DllImport("kernel32.dll")] static extern bool VirtualQueryEx(IntPtr h, long addr, out MEMORY_BASIC_INFORMATION info, int len);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public long BaseAddress;
        public long AllocationBase;
        public int AllocationProtect;
        public int __alignment1;
        public long RegionSize;
        public int State;
        public int Protect;
        public int Type;
        public int __alignment2;
    }

    static IntPtr Open(int pid) {
        return OpenProcess(0x0438, false, pid);
    }

    public static string Query(int pid, long addr) {
        IntPtr h = Open(pid);
        if (h == IntPtr.Zero) return "OpenProcess failed";
        var mbi = new MEMORY_BASIC_INFORMATION();
        bool ok = VirtualQueryEx(h, addr, out mbi, Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
        CloseHandle(h);
        if (!ok) return "VirtualQueryEx failed";
        return string.Format("base=0x{0:X} size=0x{1:X} state=0x{2:X} protect=0x{3:X} type=0x{4:X}",
            mbi.BaseAddress, mbi.RegionSize, mbi.State, mbi.Protect, mbi.Type);
    }

    public static string ReadStr(int pid, long addr, int maxBytes) {
        IntPtr h = Open(pid);
        if (h == IntPtr.Zero) return null;
        byte[] buf = new byte[maxBytes];
        long got;
        bool ok = ReadProcessMemory(h, addr, buf, maxBytes, out got);
        CloseHandle(h);
        if (!ok) return "<read failed>";
        return System.Text.Encoding.Unicode.GetString(buf).Split((char)0)[0];
    }

    // try write; if it fails, try VirtualProtectEx to RW then write, restoring old protect
    public static string WriteWithUnprotect(int pid, long addr, byte[] data) {
        IntPtr h = Open(pid);
        if (h == IntPtr.Zero) return "OpenProcess failed err=" + Marshal.GetLastWin32Error();
        long written;
        bool ok = WriteProcessMemory(h, addr, data, data.Length, out written);
        if (ok) { CloseHandle(h); return "direct write ok (" + written + " bytes)"; }
        int directErr = Marshal.GetLastWin32Error();
        int oldProt;
        bool vp = VirtualProtectEx(h, addr, data.Length, 0x04, out oldProt); // PAGE_READWRITE
        if (!vp) { CloseHandle(h); return "direct write failed err=" + directErr + "; VirtualProtectEx failed err=" + Marshal.GetLastWin32Error(); }
        ok = WriteProcessMemory(h, addr, data, data.Length, out written);
        int writeErr = Marshal.GetLastWin32Error();
        int tmp;
        VirtualProtectEx(h, addr, data.Length, oldProt, out tmp); // restore
        CloseHandle(h);
        return "after unprotect(0x" + oldProt.ToString("X") + "->RW): write ok=" + ok + " err=" + writeErr + " written=" + written;
    }
}
"@

Write-Host ("page info @ 0x" + $Address.ToString("X") + ":")
Write-Host ("  " + [MemPatch]::Query($ProcId, $Address))
Write-Host ("current string: '" + [MemPatch]::ReadStr($ProcId, $Address, 40) + "'")

if ($Apply) {
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($NewVersion)
    $payload = New-Object byte[] ($bytes.Length + 2)
    [Array]::Copy($bytes, $payload, $bytes.Length)
    Write-Host ("writing '" + $NewVersion + "' (" + $payload.Length + " bytes)...")
    Write-Host ("  " + [MemPatch]::WriteWithUnprotect($ProcId, $Address, $payload))
    Write-Host ("after string: '" + [MemPatch]::ReadStr($ProcId, $Address, 40) + "'")
}
