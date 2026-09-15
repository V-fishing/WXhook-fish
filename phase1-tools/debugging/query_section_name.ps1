param(
    [int]$ProcId = 11180,
    [long]$Address = 0x1544DFC7E30
)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class NtQVM {
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("ntdll.dll")] static extern int NtQueryVirtualMemory(IntPtr h, long addr, int infoClass, byte[] buffer, long len, out long retLen);

    public static string Query(int pid, long addr) {
        IntPtr h = OpenProcess(0x0410, false, pid);
        if (h == IntPtr.Zero) return "OpenProcess failed err=" + Marshal.GetLastWin32Error();
        byte[] buf = new byte[2048];
        long retLen;
        // MemoryMappedFilenameInformation = 2
        int st = NtQueryVirtualMemory(h, addr, 2, buf, buf.Length, out retLen);
        CloseHandle(h);
        if (st != 0) return "NtQueryVirtualMemory status=0x" + st.ToString("X8");
        // UNICODE_STRING at start: USHORT Length, USHORT MaximumLength, ULONG _pad, ULONG64 Buffer
        int len = BitConverter.ToUInt16(buf, 0);
        long strPtr = BitConverter.ToInt64(buf, 8);
        if (len == 0) return "(empty name)";
        string s = Encoding.Unicode.GetString(buf, 16, len);
        return "name='" + s + "'";
    }
}
"@

Write-Host ("MemoryMappedFilenameInformation @ 0x" + $Address.ToString("X") + " in pid " + $ProcId)
Write-Host ([NtQVM]::Query($ProcId, $Address))
