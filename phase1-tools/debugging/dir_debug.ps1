Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public class DirDebug {
    [DllImport("ntdll.dll")] static extern int NtOpenDirectoryObject(out IntPtr h, int access, ref OBJECT_ATTRIBUTES oa);
    [DllImport("ntdll.dll")] static extern int NtQueryDirectoryObject(IntPtr h, byte[] buf, int len, bool single, bool restart, ref int ctx, out int ret);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);

    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES {
        public int Length; public IntPtr RootDirectory; public IntPtr ObjectName; public int Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING {
        public ushort Length; public ushort MaximumLength; public IntPtr Buffer;
    }

    public static string Dump() {
        string dirName = @"\Sessions\1\BaseNamedObjects";
        IntPtr nameBuf = Marshal.StringToHGlobalUni(dirName);
        var us = new UNICODE_STRING();
        us.Length = (ushort)(dirName.Length * 2);
        us.MaximumLength = (ushort)(dirName.Length * 2 + 2);
        us.Buffer = nameBuf;
        IntPtr usBuf = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
        Marshal.StructureToPtr(us, usBuf, false);
        var oa = new OBJECT_ATTRIBUTES();
        oa.Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
        oa.ObjectName = usBuf;
        IntPtr hDir;
        int st = NtOpenDirectoryObject(out hDir, 0x0001, ref oa);
        Marshal.FreeHGlobal(usBuf); Marshal.FreeHGlobal(nameBuf);
        if (st != 0) return "open st=0x" + st.ToString("X8");
        var sb = new StringBuilder();
        int ctx = 0; int ret;
        byte[] buf = new byte[4096];
        for (int iter = 0; iter < 5; iter++) {
            st = NtQueryDirectoryObject(hDir, buf, buf.Length, true, false, ref ctx, out ret);
            sb.AppendLine("iter " + iter + " st=0x" + st.ToString("X8") + " ret=" + ret);
            if (st != 0) break;
            sb.Append("  raw[0..40]: ");
            for (int k = 0; k < 40; k++) sb.Append(buf[k].ToString("X2") + " ");
            sb.AppendLine();
            ushort nLen = BitConverter.ToUInt16(buf, 0);
            ushort tLen = BitConverter.ToUInt16(buf, 16);
            sb.AppendLine("  nLen=" + nLen + " tLen=" + tLen);
            if (nLen > 0 && 32 + nLen <= ret) sb.AppendLine("  name@32: '" + Encoding.Unicode.GetString(buf, 32, nLen) + "'");
            if (tLen > 0 && 32 + nLen + tLen <= ret) sb.AppendLine("  type@(32+nLen): '" + Encoding.Unicode.GetString(buf, 32 + nLen, tLen) + "'");
            // try: maybe strings are at other offsets - print a broad decode
            sb.Append("  utf16 decode of full 96 bytes: '");
            sb.Append(Encoding.Unicode.GetString(buf, 0, 96).Replace("\0", "|"));
            sb.AppendLine("'");
        }
        CloseHandle(hDir);
        return sb.ToString();
    }
}
"@

Write-Host ([DirDebug]::Dump())
