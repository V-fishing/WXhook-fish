param(
    [int]$ProcId = 28900,
    [long]$Base = 0x298BC6F7000,
    [long]$Size = 0xD9000,
    [string]$OutFile = "C:\Users\fish\ZCodeProject\blob_snapshot.bin"
)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.IO;
public class BlobDump {
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll")] static extern bool ReadProcessMemory(IntPtr h, long addr, byte[] buf, long size, out long read);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    public static long Go(int pid, long addr, long size, string outFile) {
        IntPtr h = OpenProcess(0x0410, false, pid);
        if (h == IntPtr.Zero) { Console.WriteLine("OpenProcess failed"); return -1; }
        byte[] buf = new byte[size];
        long got;
        bool ok = ReadProcessMemory(h, addr, buf, size, out got);
        CloseHandle(h);
        if (!ok) { Console.WriteLine("ReadProcessMemory failed, got=" + got); return -1; }
        File.WriteAllBytes(outFile, buf);
        return got;
    }
}
"@

$n = [BlobDump]::Go($ProcId, $Base, $Size, $OutFile)
Write-Host ("saved " + $n + " bytes to " + $OutFile)
