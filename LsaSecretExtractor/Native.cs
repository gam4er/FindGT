using System;
using System.Runtime.InteropServices;

namespace LsaSecretExtractor
{
    /// <summary>
    /// Minimal P/Invoke surface for reading an LSA private secret (e.g. $MACHINE.ACC)
    /// via the LSA Policy API. Requires SYSTEM context.
    /// </summary>
    internal static class Native
    {
        public const uint POLICY_GET_PRIVATE_INFORMATION = 0x00000004;

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint LsaOpenPolicy(
            IntPtr SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            uint DesiredAccess,
            out IntPtr PolicyHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint LsaRetrievePrivateData(
            IntPtr PolicyHandle,
            ref LSA_UNICODE_STRING KeyName,
            out IntPtr PrivateData);

        [DllImport("advapi32.dll")]
        public static extern uint LsaClose(IntPtr ObjectHandle);

        [DllImport("advapi32.dll")]
        public static extern uint LsaFreeMemory(IntPtr Buffer);

        [DllImport("advapi32.dll")]
        public static extern int LsaNtStatusToWinError(uint Status);

        public static LSA_UNICODE_STRING InitUnicodeString(string s)
        {
            LSA_UNICODE_STRING result = new LSA_UNICODE_STRING();
            result.Buffer = Marshal.StringToHGlobalUni(s);
            result.Length = (ushort)(s.Length * 2);
            result.MaximumLength = (ushort)((s.Length + 1) * 2);
            return result;
        }
    }
}
