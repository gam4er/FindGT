using Microsoft.Samples.DynamicAccessControl.Utility;

using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Microsoft.Samples.DynamicAccessControl
{
    class WinSample
    {
        /*
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct AUTHZ_RPC_INIT_INFO_CLIENT
        {
            public uint version;
            public Guid objectUuid;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string protocol;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string server;
        }*/

        internal enum AuthzRpcClientVersion : ushort // USHORT
        {
            V1 = 1
        }
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

        public static class NativeMethods
        {
            public const string AUTHZ_DLL = "authz.dll";

            [DllImport(AUTHZ_DLL, SetLastError = true, CharSet = CharSet.Unicode)]
            public static extern bool AuthzInitializeRemoteResourceManager(ref AUTHZ_RPC_INIT_INFO_CLIENT pRpcInitInfo, out IntPtr phAuthzResourceManager);

            [Flags]
            internal enum AuthzInitFlags : uint
            {
                Default = 0x0,
                SkipTokenGroups = 0x2,
                RequireS4ULogon = 0x4,
                ComputePrivileges = 0x8,
            }

            [DllImport(AUTHZ_DLL, CharSet = CharSet.Unicode, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool AuthzInitializeContextFromSid(
                AuthzInitFlags flags,
                byte [] rawUserSid,
                System.IntPtr authzRM,
                System.IntPtr expirationTime,
                ref LUID Identifier,
                System.IntPtr DynamicGroupArgs,
                out System.IntPtr authzClientContext);

            /*
            [DllImport(AUTHZ_DLL, SetLastError = true)]
            public static extern bool AuthzInitializeContextFromSid(uint Flags, byte [] UserSid, IntPtr hAuthzResourceManager, IntPtr pExpirationTime, ref LUID Identifier, IntPtr DynamicGroupArgs, out IntPtr phAuthzClientContext);
            */
            [DllImport(AUTHZ_DLL, SetLastError = true)]
            public static extern bool AuthzGetInformationFromContext(IntPtr hAuthzClientContext, AuthzContextInformationClass InfoClass, int BufferSize, out int pSizeRequired, IntPtr Buffer);

            [DllImport(AUTHZ_DLL, SetLastError = true)]
            public static extern bool AuthzFreeContext(IntPtr AuthzClientContext);

            [DllImport(AUTHZ_DLL, SetLastError = true)]
            public static extern bool AuthzFreeResourceManager(IntPtr AuthzResourceManager);
        }

        public enum AuthzContextInformationClass
        {
            AuthzContextInfoUserClaims = 13,
            AuthzContextInfoGroupsSids = 2
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_GROUPS
        {
            public uint GroupCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public SID_AND_ATTRIBUTES [] Groups;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;

            public static LUID NewLUID()
            {
                LUID luid = new LUID();
                if (!Advapi32.AllocateLocallyUniqueId(out luid))
                {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                }
                return luid;
            }
            public static LUID NullLuid
            {
                get
                {
                    LUID Empty;
                    Empty.LowPart = 0;
                    Empty.HighPart = 0;

                    return Empty;
                }
            }
        }

        public static class Advapi32
        {
            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool AllocateLocallyUniqueId(out LUID Luid);
        }

        public static class Win32Error
        {
            public const int EPT_S_NOT_REGISTERED = 1753;
            public const int ERROR_SUCCESS = 0;
        }

        static void Main(string [] args)
        {
            Console.WriteLine("Введите SID пользователя, которого надо лукапить");
            string userSidString = Console.ReadLine(); // Example SID
            Console.WriteLine("Введите домен (формата DOMAIN.LOCAL) пользователя, которого надо лукапить");
            SecurityIdentifier sid = new SecurityIdentifier(Console.ReadLine());
            byte [] sidBytes = new byte [sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);

            IntPtr authzRM = IntPtr.Zero;
            //Utility.SafeAuthzRMHandle authzRM ;
            IntPtr authzClientContext = IntPtr.Zero;

            try
            {
                // Initialize the remote resource manager
                var rpcInitInfo = new AUTHZ_RPC_INIT_INFO_CLIENT
                {
                    //objectUuid = "9a81c2bd-a525-471d-a4ed-49907c0b23da", // Replace with actual GUID
                    //objectUuid = "c2c8ffe7-5e1a-4f53-9f4a-c9e335dff0ed",
                    objectUuid = "5fc860e0-6f6e-4fc2-83cd-46324f25e90b",
                    protocol = "ncacn_ip_tcp",
                    server = "KLDC5.avp.ru"
                };

                if (!NativeMethods.AuthzInitializeRemoteResourceManager(ref rpcInitInfo, out authzRM))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error != Win32Error.EPT_S_NOT_REGISTERED)
                    {
                        throw new System.ComponentModel.Win32Exception(error);
                    }
                }

                // Initialize the client context from the SID
                LUID luid = LUID.NewLUID();
                if (!NativeMethods.AuthzInitializeContextFromSid(0, sidBytes, authzRM, IntPtr.Zero, ref luid, IntPtr.Zero, out authzClientContext))
                {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                }

                // Get the size of the buffer required for TOKEN_GROUPS
                int bufferSize = 0;
                NativeMethods.AuthzGetInformationFromContext(authzClientContext, AuthzContextInformationClass.AuthzContextInfoGroupsSids, 0, out bufferSize, IntPtr.Zero);

                if (bufferSize == 0)
                {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                }

                IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

                try
                {
                    // Get the TOKEN_GROUPS information
                    if (!NativeMethods.AuthzGetInformationFromContext(authzClientContext, AuthzContextInformationClass.AuthzContextInfoGroupsSids, bufferSize, out bufferSize, buffer))
                    {
                        throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                    }

                    TOKEN_GROUPS tokenGroups = (TOKEN_GROUPS)Marshal.PtrToStructure(buffer, typeof(TOKEN_GROUPS));
                    Console.WriteLine($"Group Count: {tokenGroups.GroupCount}");

                    // Retrieve each group SID and display it
                    IntPtr currentSidPtr = (IntPtr)((long)buffer + Marshal.OffsetOf(typeof(TOKEN_GROUPS), "Groups").ToInt32());
                    for (int i = 0; i < tokenGroups.GroupCount; i++)
                    {
                        SID_AND_ATTRIBUTES sidAndAttributes = (SID_AND_ATTRIBUTES)Marshal.PtrToStructure(currentSidPtr, typeof(SID_AND_ATTRIBUTES));
                        SecurityIdentifier groupSid = new SecurityIdentifier(sidAndAttributes.Sid);
                        Console.WriteLine($"Group {i + 1}: {groupSid.Value}");
                        currentSidPtr = (IntPtr)((long)currentSidPtr + Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES)));
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            finally
            {
                if (authzClientContext != IntPtr.Zero)
                {
                    NativeMethods.AuthzFreeContext(authzClientContext);
                }
                if (authzRM != IntPtr.Zero)
                {
                    NativeMethods.AuthzFreeResourceManager(authzRM);
                }
            }
        }
    }
}
