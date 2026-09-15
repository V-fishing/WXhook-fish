param([int]$TargetPid = 11180)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class RawQ {
    [DllImport("ntdll.dll")] static extern int NtQuerySystemInformation(int cls, IntPtr buf, int len, out int ret);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool DuplicateHandle(IntPtr srcProc, IntPtr srcHandle, IntPtr dstProc, out IntPtr dstHandle, int access, bool inherit, int options);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("ntdll.dll")] static extern int NtQueryObject(IntPtr h, int cls, byte[] buf, int len, out int ret);

    public static string Run(int pid) {
        int len = 32 * 1024 * 1024;
        IntPtr buf = Marshal.AllocHGlobal(len);
        int ret;
        int st = NtQuerySystemInformation(0x40, buf, len, out ret);
        byte[] data = new byte[len];
        Marshal.Copy(buf, data, 0, len);
        Marshal.FreeHGlobal(buf);
        ulong n = BitConverter.ToUInt64(data, 0);
        IntPtr self = GetCurrentProcess();
        IntPtr hp = OpenProcess(0x0040, false, pid);

        var sb = new StringBuilder();
        int shown = 0;
        for (int i = 0; i < (int)n && shown < 3; i++) {
            int off = 16 + i * 40;
            ulong p = BitConverter.ToUInt64(data, off + 8);
            if ((int)p != pid) continue;
            long hv = BitConverter.ToInt64(data, off + 16);
            IntPtr dup;
            if (!DuplicateHandle(hp, (IntPtr)hv, self, out dup, 0, false, 2)) continue;
            byte[] b = new byte[256];
            int r;
            int q = NtQueryObject(dup, 2, b, b.Length, out r);
            sb.AppendLine("handle=0x" + hv.ToString("X") + " NtQueryObject(ObjectTypeInfo) st=0x" + q.ToString("X8") + " retLen=" + r);
            sb.AppendLine("  Length=" + BitConverter.ToUInt16(b, 0) + " MaxLen=" + BitConverter.ToUInt16(b, 2) + " BufferPtr=0x" + BitConverter.ToInt64(b, 8).ToString("X"));
            sb.Append("  raw[0..48]: ");
            for (int k = 0; k < 48; k++) sb.Append(b[k].ToString("X2") + " ");
            sb.AppendLine();
            // try decode at offset 16
            int declen = (int)BitConverter.ToUInt16(b, 0);
            if (declen < 2) declen = 2;
            if (declen > 200) declen = 200;
            sb.AppendLine("  decode@16: '" + Encoding.Unicode.GetString(b, 16, declen) + "'");
            CloseHandle(dup);
            shown++;
        }
        CloseHandle(hp);
        return sb.ToString();
    }
}
"@

Write-Host ([RawQ]::Run($TargetPid))
