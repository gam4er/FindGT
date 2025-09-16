using System;
using System.Runtime.InteropServices;
using System.Text;

namespace FindGT
{
    public class Interop
    {
        #region enums

        public const int NO_ERROR = 0;
        public const int ERROR_INSUFFICIENT_BUFFER = 122;
        public const int ERROR_INVALID_FLAGS = 1004; // On Windows Server 2003 this error is/can be returned, but processing can still continue

        public enum SID_NAME_USE
        {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer
        }

        public enum SECURITY_LOGON_TYPE : uint
        {
            Interactive = 2,        // logging on interactively.
            Network,                // logging using a network.
            Batch,                  // logon for a batch process.
            Service,                // logon for a service account.
            Proxy,                  // Not supported.
            Unlock,                 // workstation unlock
            NetworkCleartext,       // network logon with cleartext credentials
            NewCredentials,         // caller can clone its current token and specify new credentials for outbound connections
            RemoteInteractive,      // terminal server session that is both remote and interactive
            CachedInteractive,      // attempt to use the cached credentials without going out across the network
            CachedRemoteInteractive,// same as RemoteInteractive, except used internally for auditing purposes
            CachedUnlock            // attempt to unlock a workstation
        }

        public enum MSV1_0_LOGON_SUBMIT_TYPE : uint
        {
            MsV1_0InteractiveLogon = 2,
            MsV1_0Lm20Logon,
            MsV1_0NetworkLogon,
            MsV1_0SubAuthLogon,
            MsV1_0WorkstationUnlockLogon = 7,
            MsV1_0S4ULogon = 12
        }

        public enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin
        }

        [Flags]
        public enum LuidAttributes : uint
        {
            DISABLED = 0x00000000,
            SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001,
            SE_PRIVILEGE_ENABLED = 0x00000002,
            SE_PRIVILEGE_REMOVED = 0x00000004,
            SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000
        }

        #endregion


        #region structs

        public struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 35)]
            public LUID_AND_ATTRIBUTES[] Privileges;

            public TOKEN_PRIVILEGES(uint PrivilegeCount, LUID_AND_ATTRIBUTES[] Privileges)
            {
                this.PrivilegeCount = PrivilegeCount;
                this.Privileges = Privileges;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public UInt32 Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_GROUPS
        {
            public UInt32 GroupCount;
            [MarshalAs(UnmanagedType.ByValArray)]
            public SID_AND_ATTRIBUTES[] Groups;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_ORIGIN
        {
            public LUID LoginID;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIMARY_GROUP
        {
            public IntPtr PrimaryGroup;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public UInt32 Attributes;

            public const UInt32 SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
            public const UInt32 SE_PRIVILEGE_ENABLED = 0x00000002;
            public const UInt32 SE_PRIVILEGE_REMOVED = 0x00000004;
            public const UInt32 SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_LOGON_SESSION_DATA
        {
            public uint Size;
            public LUID LoginID;
            public LSA_STRING Username;
            public LSA_STRING LoginDomain;
            public LSA_STRING AuthenticationPackage;
            public uint LogonType;
            public uint Session;
            public IntPtr PSiD;
            public ulong LoginTime;
            public LSA_STRING LogonServer;
            public LSA_STRING DnsDomainName;
            public LSA_STRING Upn;
        }

        public struct SECURITY_INTEGER
        {
            public uint LowPart;
            public int HighPart;
            public static SECURITY_INTEGER Empty
            {
                get
                {
                    return new SECURITY_INTEGER
                    {
                        LowPart = 0,
                        HighPart = 0
                    };
                }
            }
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct FILETIME
        {
            public uint DateTimeLow;
            public uint DateTimeHigh;
        }

        public struct SECURITY_HANDLE
        {
            public IntPtr LowPart;
            public IntPtr HighPart;

            public static SECURITY_HANDLE Empty
            {
                get
                {
                    return new SECURITY_HANDLE
                    {
                        LowPart = IntPtr.Zero,
                        HighPart = IntPtr.Zero
                    };
                }
            }
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_SOURCE
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] SourceName;
            public LUID SourceIdentifier;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct QUOTA_LIMITS
        {
            public UIntPtr PagedPoolLimit;
            public UIntPtr NonPagedPoolLimit;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public UIntPtr PagefileLimit;
            public long TimeLimit;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MSV1_0_S4U_LOGON
        {
            public MSV1_0_LOGON_SUBMIT_TYPE MessageType;
            public uint Flags;
            public UNICODE_STRING UserPrincipalName;
            public UNICODE_STRING DomainName;
        }

        #endregion


        #region APIs


        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool ConvertSidToStringSid(
            [MarshalAs(UnmanagedType.LPArray)] byte[] pSID,
            out IntPtr ptrSid);

        [DllImport("kernel32.dll")]
        public static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("kernel32", EntryPoint = "GetComputerNameA", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern bool GetComputerName(StringBuilder lpBuffer, ref int nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateFile(
               string lpFileName,
               uint dwDesiredAccess,
               uint dwShareMode,
               uint lpSecurityAttributes,
               uint dwCreationDisposition,
               uint dwFlagsAndAttributes,
               uint hTemplateFile);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WriteFile(
            IntPtr hFile,
            byte[] lpBuffer,
            uint nNumberOfBytesToWrite,
            out uint lpNumberOfBytesWritten,
            IntPtr lpOverlapped);

        [DllImport("secur32.dll", CharSet = CharSet.Auto)]
        public static extern uint AcquireCredentialsHandle(
            string pszPrincipal,
            string pszPackage,
            int fCredentialUse,
            IntPtr PAuthenticationID,
            IntPtr pAuthData,
            IntPtr pGetKeyFn,
            IntPtr pvGetKeyArgument,
            ref SECURITY_HANDLE phCredential,
            ref FILETIME ptsExpiry
        );

        [DllImport("secur32.dll", SetLastError = true)]
        public static extern uint InitializeSecurityContext(
            ref SECURITY_HANDLE phCredential,
            IntPtr phContext,
            string pszTargetName,
            int fContextReq,
            int Reserved1,
            int TargetDataRep,
            IntPtr pInput,
            int Reserved2,
            out SECURITY_HANDLE phNewContext,
            out SecBufferDesc pOutput,
            out uint pfContextAttr,
            out SECURITY_INTEGER ptsExpiry
        );

        [DllImport("secur32.dll", SetLastError = true)]
        public static extern uint InitializeSecurityContext(
            ref SECURITY_HANDLE phCredential,
            ref SECURITY_HANDLE phContext,
            string pszTargetName,
            int fContextReq,
            int Reserved1,
            int TargetDataRep,
            ref SecBufferDesc SecBufferDesc,
            int Reserved2,
            out SECURITY_HANDLE phNewContext,
            out SecBufferDesc pOutput,
            out uint pfContextAttr,
            out SECURITY_INTEGER ptsExpiry
        );

        [DllImport("secur32.dll", SetLastError = true)]
        public static extern uint AcceptSecurityContext(
            ref SECURITY_HANDLE phCredential,
            IntPtr phContext,
            ref SecBufferDesc pInput,
            uint fContextReq,
            uint TargetDataRep,
            out SECURITY_HANDLE phNewContext,
            out SecBufferDesc pOutput,
            out uint pfContextAttr,
            out SECURITY_INTEGER ptsTimeStamp
        );

        [DllImport("secur32.dll", SetLastError = true)]
        public static extern uint AcceptSecurityContext(
            ref SECURITY_HANDLE phCredential,
            ref SECURITY_HANDLE phContext,
            ref SecBufferDesc pInput,
            uint fContextReq,
            uint TargetDataRep,
            out SECURITY_HANDLE phNewContext,
            out SecBufferDesc pOutput,
            out uint pfContextAttr,
            out SECURITY_INTEGER ptsTimeStamp
        );

        [DllImport("Secur32.dll", SetLastError = true)]
        public static extern uint QuerySecurityContextToken(
            SECURITY_HANDLE phContext,
            out IntPtr phToken
        );

        [DllImport("Secur32.dll", SetLastError = true)]
        public static extern uint QueryCredentialsAttributes(
            ref SECURITY_HANDLE phCredential,
            ulong ulAttribute,
            out IntPtr pBuffer
        );

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern uint LsaFreeReturnBuffer(
            IntPtr buffer
        );

        [DllImport("Secur32.dll", SetLastError = false)]
        public static extern uint LsaEnumerateLogonSessions(
            out UInt64 LogonSessionCount,
            out IntPtr LogonSessionList
        );

        [DllImport("Secur32.dll", SetLastError = false)]
        public static extern uint LsaGetLogonSessionData(
            IntPtr luid,
            out IntPtr ppLogonSessionData
        );

        [DllImport("Secur32.dll", SetLastError = false)]
        public static extern uint LsaRegisterLogonProcess(
            ref LSA_STRING LogonProcessName,
            out IntPtr LsaHandle,
            out ulong SecurityMode
        );

        [DllImport("Secur32.dll", SetLastError = false)]
        public static extern uint LsaDeregisterLogonProcess(
            IntPtr LsaHandle
        );

        [DllImport("Secur32.dll", SetLastError = false)]
        public static extern uint LsaLookupAuthenticationPackage(
            IntPtr LsaHandle,
            ref LSA_STRING PackageName,
            out uint AuthenticationPackage
        );

        [DllImport("Secur32.dll", SetLastError = false)]
        public static extern uint LsaLogonUser(
            IntPtr LsaHandle,
            ref LSA_STRING OriginName,
            SECURITY_LOGON_TYPE LogonType,
            uint AuthenticationPackage,
            IntPtr AuthenticationInformation,
            uint AuthenticationInformationLength,
            IntPtr LocalGroups,
            ref TOKEN_SOURCE SourceContext,
            out IntPtr ProfileBuffer,
            out uint ProfileBufferLength,
            out LUID LogonId,
            out IntPtr Token,
            out QUOTA_LIMITS Quotas,
            out uint SubStatus
        );

        [DllImport("Advapi32.dll", SetLastError = false)]
        public static extern uint LsaNtStatusToWinError(uint Status);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AllocateLocallyUniqueId(out LUID Luid);


        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            out int ReturnLength
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            UInt32 DesiredAccess,
            out IntPtr TokenHandle
        );

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool ConvertSidToStringSid(
            IntPtr securityIdentifier,
            out string securityIdentifierName
        );

        [DllImport("advapi32.dll")]
        public static extern bool DuplicateToken(
            IntPtr ExistingTokenHandle,
            int SECURITY_IMPERSONATION_LEVEL,
            ref IntPtr DuplicateTokenHandle
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateLoggedOnUser(
            IntPtr hToken
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool RevertToSelf();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(
            IntPtr hObject
        );

        [DllImport("secur32.dll", SetLastError = true)]
        public static extern bool FreeCredentialsHandle(
            ref SECURITY_HANDLE phCredential
        );

        [DllImport("secur32.dll", SetLastError = true)]
        public static extern bool DeleteSecurityContext(
            ref SECURITY_HANDLE phContext
        );

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool LookupAccountSid(
            string lpSystemName,
            [MarshalAs(UnmanagedType.LPArray)] byte[] lpSid,
            StringBuilder lpName,
            ref uint cchName,
            StringBuilder lpReferencedDomainName,
            ref uint cchReferencedDomainName,
            out uint peUse);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LookupAccountName(
            string lpSystemName,
            string lpAccountName,
            [MarshalAs(UnmanagedType.LPArray)] byte[] Sid,
            ref uint cbSid,
            StringBuilder ReferencedDomainName,
            ref uint cchReferencedDomainName,
            out SID_NAME_USE peUse);

        #endregion
    }
}
