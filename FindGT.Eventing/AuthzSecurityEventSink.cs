using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using FindGT.Core;

namespace FindGT.Eventing
{
    public enum SecuritySinkMode
    {
        Off,
        SuspiciousOnly,
        All
    }

    internal sealed class AuthzSecurityEventSink : IDisposable
    {
        private const uint SecurityAuditEventId = 2000;
        private const uint AuditSuccess = 1;
        private readonly SecuritySinkMode _mode;
        private SafeAuthzProviderHandle _provider;

        internal AuthzSecurityEventSink(SecuritySinkMode mode)
        {
            _mode = mode;
            if (_mode == SecuritySinkMode.Off)
            {
                return;
            }

            string privilegeError;
            if (!TokenPrivilege.TryEnable("SeAuditPrivilege", out privilegeError))
            {
                InitializationError = privilegeError;
                return;
            }

            IntPtr rawProvider;
            if (!AuthzRegisterSecurityEventSource(
                0,
                "FindGT",
                out rawProvider))
            {
                InitializationError = new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "AuthzRegisterSecurityEventSource failed.").Message;
                return;
            }

            _provider = new SafeAuthzProviderHandle(rawProvider);
        }

        internal bool IsAvailable
        {
            get
            {
                return _mode != SecuritySinkMode.Off &&
                    _provider != null &&
                    !_provider.IsInvalid &&
                    !_provider.IsClosed;
            }
        }

        internal string InitializationError { get; private set; }

        internal bool ShouldWrite(SessionAnalysisResult result)
        {
            return _mode == SecuritySinkMode.All ||
                (_mode == SecuritySinkMode.SuspiciousOnly &&
                 result.Verdict == AnalysisVerdict.Suspicious);
        }

        internal bool Write(
            SessionAnalysisResult result,
            string payload,
            out string error)
        {
            if (!ShouldWrite(result))
            {
                error = null;
                return true;
            }

            if (!IsAvailable)
            {
                error = InitializationError ??
                    "The Authz Security event provider is unavailable.";
                return false;
            }

            IntPtr stringBuffer = IntPtr.Zero;
            IntPtr parameterBuffer = IntPtr.Zero;
            IntPtr sidBuffer = IntPtr.Zero;
            try
            {
                stringBuffer = Marshal.StringToHGlobalUni(payload ?? String.Empty);
                AuditParam parameter = new AuditParam
                {
                    Type = AuditParamType.String,
                    Data0 = ToUIntPtr(stringBuffer)
                };
                parameterBuffer = Marshal.AllocHGlobal(
                    Marshal.SizeOf(typeof(AuditParam)));
                Marshal.StructureToPtr(parameter, parameterBuffer, false);

                AuditParams parameters = new AuditParams
                {
                    Length = (uint)Marshal.SizeOf(typeof(AuditParams)),
                    Flags = AuditSuccess,
                    Count = 1,
                    Parameters = parameterBuffer
                };

                if (result.Session != null &&
                    !String.IsNullOrWhiteSpace(result.Session.UserSid))
                {
                    SecurityIdentifier sid = new SecurityIdentifier(
                        result.Session.UserSid);
                    byte[] binarySid = new byte[sid.BinaryLength];
                    sid.GetBinaryForm(binarySid, 0);
                    sidBuffer = Marshal.AllocHGlobal(binarySid.Length);
                    Marshal.Copy(binarySid, 0, sidBuffer, binarySid.Length);
                }

                if (AuthzReportSecurityEventFromParams(
                    0,
                    _provider.DangerousGetHandle(),
                    SecurityAuditEventId,
                    sidBuffer,
                    ref parameters))
                {
                    error = null;
                    return true;
                }

                error = new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "AuthzReportSecurityEventFromParams failed.").Message;
                return false;
            }
            catch (ArgumentException exception)
            {
                error = exception.Message;
                return false;
            }
            finally
            {
                if (sidBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(sidBuffer);
                }

                if (parameterBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(parameterBuffer);
                }

                if (stringBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(stringBuffer);
                }
            }
        }

        public void Dispose()
        {
            _provider?.Dispose();
            _provider = null;
        }

        internal static bool TryParseMode(
            string value,
            out SecuritySinkMode mode)
        {
            return Enum.TryParse(value, true, out mode);
        }

        private static UIntPtr ToUIntPtr(IntPtr value)
        {
            return UIntPtr.Size == 8
                ? new UIntPtr(unchecked((ulong)value.ToInt64()))
                : new UIntPtr(unchecked((uint)value.ToInt32()));
        }

        internal enum AuditParamType
        {
            None = 1,
            String = 2
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct AuditParam
        {
            internal AuditParamType Type;
            internal uint Length;
            internal uint Flags;
            internal UIntPtr Data0;
            internal UIntPtr Data1;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct AuditParams
        {
            internal uint Length;
            internal uint Flags;
            internal ushort Count;
            internal IntPtr Parameters;
        }

        [DllImport(
            "authz.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AuthzRegisterSecurityEventSource(
            uint flags,
            string eventSourceName,
            out IntPtr eventProvider);

        [DllImport("authz.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AuthzUnregisterSecurityEventSource(
            uint flags,
            ref IntPtr eventProvider);

        [DllImport("authz.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AuthzReportSecurityEventFromParams(
            uint flags,
            IntPtr eventProvider,
            uint auditId,
            IntPtr userSid,
            ref AuditParams parameters);

        private sealed class SafeAuthzProviderHandle :
            SafeHandleZeroOrMinusOneIsInvalid
        {
            internal SafeAuthzProviderHandle(IntPtr value)
                : base(true)
            {
                SetHandle(value);
            }

            protected override bool ReleaseHandle()
            {
                IntPtr value = handle;
                bool success = AuthzUnregisterSecurityEventSource(
                    0,
                    ref value);
                SetHandle(IntPtr.Zero);
                return success;
            }
        }
    }

    internal static class TokenPrivilege
    {
        private const uint TokenAdjustPrivileges = 0x0020;
        private const uint TokenQuery = 0x0008;
        private const uint SePrivilegeEnabled = 0x00000002;
        private const int ErrorNotAllAssigned = 1300;

        internal static bool TryEnable(string privilege, out string error)
        {
            IntPtr rawToken;
            if (!OpenProcessToken(
                GetCurrentProcess(),
                TokenAdjustPrivileges | TokenQuery,
                out rawToken))
            {
                error = new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "OpenProcessToken failed.").Message;
                return false;
            }

            using (SafeTokenHandle token = new SafeTokenHandle(rawToken))
            {
                NativeLuid luid;
                if (!LookupPrivilegeValue(null, privilege, out luid))
                {
                    error = new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "LookupPrivilegeValue failed.").Message;
                    return false;
                }

                TokenPrivileges state = new TokenPrivileges
                {
                    PrivilegeCount = 1,
                    Privilege = new LuidAndAttributes
                    {
                        Luid = luid,
                        Attributes = SePrivilegeEnabled
                    }
                };
                if (!AdjustTokenPrivileges(
                    token.DangerousGetHandle(),
                    false,
                    ref state,
                    0,
                    IntPtr.Zero,
                    IntPtr.Zero))
                {
                    error = new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "AdjustTokenPrivileges failed.").Message;
                    return false;
                }

                int lastError = Marshal.GetLastWin32Error();
                if (lastError == ErrorNotAllAssigned)
                {
                    error = "SeAuditPrivilege is not assigned to the service token.";
                    return false;
                }
            }

            error = null;
            return true;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct NativeLuid
        {
            internal uint LowPart;
            internal int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LuidAndAttributes
        {
            internal NativeLuid Luid;
            internal uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TokenPrivileges
        {
            internal uint PrivilegeCount;
            internal LuidAndAttributes Privilege;
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenProcessToken(
            IntPtr process,
            uint desiredAccess,
            out IntPtr token);

        [DllImport(
            "advapi32.dll",
            EntryPoint = "LookupPrivilegeValueW",
            CharSet = CharSet.Unicode,
            ExactSpelling = true,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool LookupPrivilegeValue(
            string systemName,
            string name,
            out NativeLuid luid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AdjustTokenPrivileges(
            IntPtr token,
            [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges,
            ref TokenPrivileges newState,
            uint bufferLength,
            IntPtr previousState,
            IntPtr returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        private sealed class SafeTokenHandle :
            SafeHandleZeroOrMinusOneIsInvalid
        {
            internal SafeTokenHandle(IntPtr value)
                : base(true)
            {
                SetHandle(value);
            }

            protected override bool ReleaseHandle()
            {
                return CloseHandle(handle);
            }
        }
    }
}
