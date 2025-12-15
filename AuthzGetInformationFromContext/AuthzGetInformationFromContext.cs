using Microsoft.Samples.DynamicAccessControl.Utility;
using Microsoft.Win32.SafeHandles;

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.DirectoryServices.AccountManagement;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Principal;

using static AuthzGetInformationFromContext.NativeMethods;

using AUTHZ_CLIENT_CONTEXT_HANDLE = System.IntPtr;
using PAUTHZ_RPC_INIT_INFO_CLIENT = System.IntPtr;

using DWORD = System.UInt32;
using ULONG = System.UInt32;

using LPVOID = System.IntPtr;
using PUCHAR = System.IntPtr;
using PDWORD = System.IntPtr;

using PSID = System.IntPtr;
using PACL = System.IntPtr;
using PLARGE_INTEGER = System.IntPtr;
using PSECURITY_DESCRIPTOR = System.IntPtr;

using AUTHZ_RESOURCE_MANAGER_HANDLE = System.IntPtr;
using AUTHZ_AUDIT_EVENT_HANDLE = System.IntPtr;
using AUTHZ_ACCESS_CHECK_RESULTS_HANDLE = System.IntPtr;
using POBJECT_TYPE_LIST = System.IntPtr;
using PACCESS_MASK = System.IntPtr;
using System.Runtime.Remoting.Contexts;
using System.Data.SqlTypes;



namespace AuthzGetInformationFromContext
{

    internal class AuthzGetInformationFromContext
    {
        static void Main(string [] args)
        {
            try
            {
                string userSidString = "";
                string dcName = "";
                string [] groupSids = AuthzWrapper.GetUserGroupSids(userSidString, dcName);

                Console.WriteLine("Groups:");
                foreach (string groupSid in groupSids)
                {
                    Console.WriteLine(groupSid);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred: " + ex.Message);
            }
        }
    }
    public class AuthzWrapper
    {
        private const int ERROR_INSUFFICIENT_BUFFER = 122;
        private const int AuthzContextInfoGroupsSids = 2;

        #region Dll imports
        [DllImport("authz.dll", SetLastError = true)]
        private static extern bool AuthzInitializeContextFromSid(
            uint Flags,
            IntPtr Sid,
            IntPtr AuthzResourceManager,
            IntPtr pExpirationTime,
            ref LUID Identifier,
            IntPtr DynamicGroupArgs,
            out IntPtr pAuthzClientContext
        );

        [DllImport("authz.dll", SetLastError = true)]
        private static extern bool AuthzInitializeRemoteResourceManager(
            IntPtr AuthzRpcInitInfo,
            out IntPtr ResourceManager
        );

        [DllImport("authz.dll", SetLastError = true)]
        private static extern bool AuthzGetInformationFromContext(
            IntPtr hAuthzClientContext,
            int InfoClass,
            int BufferSize,
            out int pSizeRequired,
            IntPtr Buffer
        );

        [DllImport("authz.dll", SetLastError = true)]
        private static extern bool AuthzFreeContext(IntPtr hAuthzClientContext);

        [DllImport("authz.dll", SetLastError = true)]
        private static extern bool AuthzFreeResourceManager(IntPtr hAuthzResourceManager);

        #endregion

        public static string [] GetUserGroupSids(string userSidString, string dcName)

        {
            AUTHZ_CLIENT_CONTEXT_HANDLE userClientCtxt = AUTHZ_CLIENT_CONTEXT_HANDLE.Zero;
            AUTHZ_CLIENT_CONTEXT_HANDLE deviceClientCtxt = AUTHZ_CLIENT_CONTEXT_HANDLE.Zero;
            AUTHZ_CLIENT_CONTEXT_HANDLE compoundCtxt = AUTHZ_CLIENT_CONTEXT_HANDLE.Zero;

            try
            {
                var rpcInitInfo = new NativeMethods.AUTHZ_RPC_INIT_INFO_CLIENT();

                rpcInitInfo.version = NativeMethods.AuthzRpcClientVersion.V1;
                rpcInitInfo.objectUuid = "9a81c2bd-a525-471d-a4ed-49907c0b23da";
                rpcInitInfo.protocol = NativeMethods.RCP_OVER_TCP_PROTOCOL;
                rpcInitInfo.server = "";

                SafeAuthzRMHandle authzRM;

                SafeHGlobalHandle pRpcInitInfo = SafeHGlobalHandle.AllocHGlobalStruct(rpcInitInfo);
                if (!NativeMethods.AuthzInitializeRemoteResourceManager(pRpcInitInfo.ToIntPtr(), out authzRM))
                {
                    int error = Marshal.GetLastWin32Error();

                    if (error != Win32Error.EPT_S_NOT_REGISTERED)
                    {
                        throw new Win32Exception(error);
                    }

                }
                SecurityIdentifier userSid = new SecurityIdentifier(userSidString);

                byte [] rawSid = new byte [userSid.BinaryLength];
                userSid.GetBinaryForm(rawSid, 0);
                SafeHGlobalHandle prawSid = SafeHGlobalHandle.AllocHGlobal(rawSid);
                IntPtr authzClientContext = IntPtr.Zero;

                if (!NativeMethods.AuthzInitializeContextFromSid(0, rawSid, authzRM, IntPtr.Zero, Win32.LUID.NewLUID(), IntPtr.Zero, out authzClientContext))
                {
                    Win32Exception win32Expn = new Win32Exception(Marshal.GetLastWin32Error());

                    if (win32Expn.NativeErrorCode != Win32Error.RPC_S_SERVER_UNAVAILABLE)
                    {
                        throw win32Expn;
                    }
                }

                //
                // Create an AuthZ context based on the user account
                //
                if (!NativeMethods.AuthzInitializeContextFromSid(NativeMethods.AuthzInitFlags.Default,
                                                                 rawSid,
                                                                 authzRM,
                                                                 PLARGE_INTEGER.Zero,
                                                                 new Win32.LUID(),
                                                                 LPVOID.Zero,
                                                                 out userClientCtxt))
                {
                    Win32Exception win32Expn = new Win32Exception(Marshal.GetLastWin32Error());

                    if (win32Expn.NativeErrorCode != Win32Error.RPC_S_SERVER_UNAVAILABLE)
                    {
                        throw win32Expn;
                    }

                    Helper.LogWarning(string.Format(CultureInfo.CurrentCulture,
                                              "{0}. Please enable the inward firewall rule: Netlogon Service " +
                                              "Authz(RPC), on the target machine and try again.", win32Expn.Message),
                                      true);
                    return null;
                }

                bool success = AuthzGetInformationFromContext(userClientCtxt, AuthzContextInfoGroupsSids, 0, out var sizeRequired, IntPtr.Zero);
                Win32Exception LastError = new Win32Exception(Marshal.GetLastWin32Error());
                if (!success && LastError.NativeErrorCode != Win32Error.ERROR_INSUFFICIENT_BUFFER && LastError.NativeErrorCode != Win32Error.ERROR_SUCCESS)
                    return null;
                

                if (sizeRequired == 0)
                {
                    Console.WriteLine("No context information available?");
                    return null;
                }

                IntPtr buffer = IntPtr.Zero;
                buffer = Marshal.AllocHGlobal(sizeRequired);
                int bufferSize = sizeRequired;
                if (!AuthzGetInformationFromContext(userClientCtxt, AuthzContextInfoGroupsSids, bufferSize, out sizeRequired, buffer))
                {
                    Marshal.FreeHGlobal(buffer);
                    AuthzFreeContext(userClientCtxt);
                    authzRM.Dispose();
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                }
                

                // Process buffer to get SIDs
                int count = sizeRequired / Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));
                SID_AND_ATTRIBUTES [] groups = new SID_AND_ATTRIBUTES [count];
                IntPtr current = buffer;
                for (int i = 0; i < count; i++)
                {
                    groups [i] = Marshal.PtrToStructure<SID_AND_ATTRIBUTES>(current);
                    current = IntPtr.Add(current, Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES)));
                }

                string [] groupSids = new string [groups.Length];
                for (int i = 0; i < groups.Length; i++)
                {
                    groupSids [i] = new SecurityIdentifier(groups [i].Sid).Value;
                }

                // Cleanup
                Marshal.FreeHGlobal(buffer);
                AuthzFreeContext(userClientCtxt);                

                return groupSids;

            }
            finally
            {
                if (userClientCtxt != AUTHZ_CLIENT_CONTEXT_HANDLE.Zero)
                {
                    NativeMethods.AuthzFreeContext(userClientCtxt);
                    userClientCtxt = AUTHZ_CLIENT_CONTEXT_HANDLE.Zero;
                }

                if (deviceClientCtxt != AUTHZ_CLIENT_CONTEXT_HANDLE.Zero)
                {
                    NativeMethods.AuthzFreeContext(deviceClientCtxt);
                    deviceClientCtxt = AUTHZ_CLIENT_CONTEXT_HANDLE.Zero;

                    if (compoundCtxt != AUTHZ_CLIENT_CONTEXT_HANDLE.Zero)
                    {
                        NativeMethods.AuthzFreeContext(compoundCtxt);
                        compoundCtxt = AUTHZ_CLIENT_CONTEXT_HANDLE.Zero;
                    }
                }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public uint HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public uint Attributes;
        }

    }
    static class NativeMethods
    {
        #region authz
        [StructLayout(LayoutKind.Sequential)]
        internal struct AUTHZ_ACCESS_REQUEST
        {
            public StdAccess DesiredAccess;
            public byte [] PrincipalSelfSid;
            public POBJECT_TYPE_LIST ObjectTypeList;
            public int ObjectTypeListLength;
            public LPVOID OptionalArguments;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct AUTHZ_ACCESS_REPLY
        {
            public int ResultListLength;
            public PACCESS_MASK GrantedAccessMask;
            public PDWORD SaclEvaluationResults;
            public PDWORD Error;
        }

        internal enum AuthzACFlags : uint // DWORD
        {
            None = 0,
            NoDeepCopySD
        }

        [DllImport(Win32.AUTHZ_DLL, CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzAccessCheck(
            AuthzACFlags flags,
            AUTHZ_CLIENT_CONTEXT_HANDLE hAuthzClientContext,
            ref AUTHZ_ACCESS_REQUEST pRequest,
            AUTHZ_AUDIT_EVENT_HANDLE AuditEvent,
            byte [] rawSecurityDescriptor,
            PSECURITY_DESCRIPTOR [] OptionalSecurityDescriptorArray,
            DWORD OptionalSecurityDescriptorCount,
            ref AUTHZ_ACCESS_REPLY pReply,
            AUTHZ_ACCESS_CHECK_RESULTS_HANDLE cachedResults);

        [DllImport(Win32.AUTHZ_DLL, CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzFreeContext(AUTHZ_CLIENT_CONTEXT_HANDLE authzClientContext);

        internal enum AuthzRpcClientVersion : ushort // USHORT
        {
            V1 = 1
        }

        internal const string AUTHZ_OBJECTUUID_WITHCAP = "9a81c2bd-a525-471d-a4ed-49907c0b23da";

        internal const string RCP_OVER_TCP_PROTOCOL = "ncacn_ip_tcp";

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct AUTHZ_RPC_INIT_INFO_CLIENT
        {
            public AuthzRpcClientVersion version;
            public string objectUuid;
            public string protocol;
            public string server;
            public string endPoint;
            public string options;
            public string serverSpn;
        }

        [DllImport(Win32.AUTHZ_DLL, CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzInitializeRemoteResourceManager(
            PAUTHZ_RPC_INIT_INFO_CLIENT rpcInitInfo,
            out SafeAuthzRMHandle authRM);

        [Flags]
        internal enum AuthzInitFlags : uint
        {
            Default = 0x0,
            SkipTokenGroups = 0x2,
            RequireS4ULogon = 0x4,
            ComputePrivileges = 0x8,
        }

        [DllImport(Win32.AUTHZ_DLL, CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzInitializeContextFromSid(
            AuthzInitFlags flags,
            byte [] rawUserSid,
            SafeAuthzRMHandle authzRM,
            PLARGE_INTEGER expirationTime,
            Win32.LUID Identifier,
            LPVOID DynamicGroupArgs,
            out AUTHZ_CLIENT_CONTEXT_HANDLE authzClientContext);

        [DllImport(Win32.AUTHZ_DLL, CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzInitializeCompoundContext(
            AUTHZ_CLIENT_CONTEXT_HANDLE userClientContext,
            AUTHZ_CLIENT_CONTEXT_HANDLE deviceClientContext,
            out AUTHZ_CLIENT_CONTEXT_HANDLE compoundContext);

        [Flags]
        internal enum AuthzResourceManagerFlags : uint
        {
            NO_AUDIT = 0x1,
        }

        [DllImport(Win32.AUTHZ_DLL, CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzInitializeResourceManager(
            AuthzResourceManagerFlags flags,
            IntPtr pfnAccessCheck,
            IntPtr pfnComputeDynamicGroups,
            IntPtr pfnFreeDynamicGroups,
            string szResourceManagerName,
            out SafeAuthzRMHandle phAuthzResourceManager);

        #endregion

        #region PInvoke kernel32
        [Flags]
        internal enum StdAccess : uint
        {
            None = 0x0,

            SYNCHRONIZE = 0x100000,
            STANDARD_RIGHTS_REQUIRED = 0xF0000,

            MAXIMUM_ALLOWED = 0x2000000,
        }

        [Flags]
        internal enum FileAccess : uint
        {
            None = 0x0,
            ReadData = 0x1,
            WriteData = 0x2,
            AppendData = 0x4,
            ReadExAttrib = 0x8,
            WriteExAttrib = 0x10,
            Execute = 0x20,
            DeleteChild = 0x40,
            ReadAttrib = 0x80,
            WriteAttrib = 0x100,

            Delete = 0x10000,   // DELETE,
            ReadPermissions = 0x20000,   // READ_CONTROL
            ChangePermissions = 0x40000,   // WRITE_DAC,
            TakeOwnership = 0x80000,   // WRITE_OWNER,

            GenericRead = ReadPermissions
                        | ReadData
                        | ReadAttrib
                        | ReadExAttrib
                        | StdAccess.SYNCHRONIZE,

            GenericAll = (StdAccess.STANDARD_RIGHTS_REQUIRED | 0x1FF),

            CategoricalAll = uint.MaxValue
        }

        [Flags]
        internal enum FileShare : uint
        {
            None = 0x0,
            Read = 0x1,
            Write = 0x2,
            Delete = 0x4
        }

        internal enum FileMode : uint
        {
            OpenExisting = 3,
        }

        [Flags]
        internal enum FileFlagAttrib : uint
        {
            BackupSemantics = 0x02000000,
        }

        [DllImport(Win32.KERNEL32_DLL, SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern SafeFileHandle CreateFile(string lpFileName,
                                                         FileAccess desiredAccess,
                                                         FileShare shareMode,
                                                         IntPtr lpSecurityAttributes,
                                                         FileMode mode,
                                                         FileFlagAttrib flagsAndAttributes,
                                                         IntPtr hTemplateFile);
        #endregion

        #region PInvoke advapi32
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct ACE_HEADER
        {
            public byte AceType;
            public byte AceFlags;
            public ushort AceSize;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct SYSTEM_SCOPED_POLICY_ID_ACE
        {
            public ACE_HEADER Header;
            public uint Mask;
            public uint SidStart;
        }

        internal enum ObjectType : uint
        {
            File = 1,
        }

        [Flags]
        internal enum SecurityInformationClass : uint
        {
            Owner = 0x00001,
            Group = 0x00002,
            Dacl = 0x00004,
            Sacl = 0x00008,
            Label = 0x00010,
            Attribute = 0x00020,
            Scope = 0x00040
        }

        [DllImport(Win32.ADVAPI32_DLL, CallingConvention = CallingConvention.Winapi, SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern DWORD GetSecurityInfo(
            SafeFileHandle handle,
            ObjectType objectType,
            SecurityInformationClass infoClass,
            PSID owner,
            PSID group,
            PACL dacl,
            PACL sacl,
            out PSECURITY_DESCRIPTOR securityDescriptor);
        #endregion
    }
}
