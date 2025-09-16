using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

namespace FindGT
{
    public class Helpers
    {
        private const string Version = "1.0.0";

        public static List<string> GetTokenGroups(IntPtr token)
        {
            // returns an arraylist of all of the group SIDs present for a specified token

            List<string> groupSids = new List<string>();

            try
            {
                IntPtr pGroups = GetTokenInfo(token, Interop.TOKEN_INFORMATION_CLASS.TokenGroups);

                Interop.TOKEN_GROUPS groups = (Interop.TOKEN_GROUPS)Marshal.PtrToStructure(pGroups, typeof(Interop.TOKEN_GROUPS));
                string[] userSIDS = new string[groups.GroupCount];
                int sidAndAttrSize = Marshal.SizeOf(new Interop.SID_AND_ATTRIBUTES());

                for (int i = 0; i < groups.GroupCount; i++)
                {
                    Interop.SID_AND_ATTRIBUTES sidAndAttributes = (Interop.SID_AND_ATTRIBUTES)Marshal.PtrToStructure(
                        new IntPtr(pGroups.ToInt64() + i * sidAndAttrSize + IntPtr.Size), typeof(Interop.SID_AND_ATTRIBUTES));

                    string sidString = "";
                    Interop.ConvertSidToStringSid(sidAndAttributes.Sid, out sidString);

                    groupSids.Add(sidString);
                }

                Marshal.FreeHGlobal(pGroups);
            }
            catch { }

            return groupSids;
        }

        public struct TokenGroup
        {
            public SecurityIdentifier Sid;
            public uint Attributes;
        }

        public static List<TokenGroup> GetTokenGroupsWithAttributes(IntPtr token)
        {
            List<TokenGroup> groups = new List<TokenGroup>();
            IntPtr pGroups = IntPtr.Zero;

            try
            {
                pGroups = GetTokenInfo(token, Interop.TOKEN_INFORMATION_CLASS.TokenGroups);
                Interop.TOKEN_GROUPS tokenGroups = (Interop.TOKEN_GROUPS)Marshal.PtrToStructure(pGroups, typeof(Interop.TOKEN_GROUPS));

                int sidAndAttrSize = Marshal.SizeOf(typeof(Interop.SID_AND_ATTRIBUTES));
                IntPtr groupsPtr = new IntPtr(pGroups.ToInt64() + Marshal.OffsetOf(typeof(Interop.TOKEN_GROUPS), "Groups").ToInt64());

                for (int i = 0; i < tokenGroups.GroupCount; i++)
                {
                    IntPtr entryPtr = new IntPtr(groupsPtr.ToInt64() + sidAndAttrSize * i);
                    Interop.SID_AND_ATTRIBUTES sidAndAttributes = (Interop.SID_AND_ATTRIBUTES)Marshal.PtrToStructure(entryPtr, typeof(Interop.SID_AND_ATTRIBUTES));

                    if (sidAndAttributes.Sid != IntPtr.Zero)
                    {
                        groups.Add(new TokenGroup
                        {
                            Sid = new SecurityIdentifier(sidAndAttributes.Sid),
                            Attributes = sidAndAttributes.Attributes
                        });
                    }
                }
            }
            finally
            {
                if (pGroups != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pGroups);
                }
            }

            return groups;
        }

        public static SecurityIdentifier GetTokenPrimaryGroup(IntPtr token)
        {
            IntPtr pPrimaryGroup = IntPtr.Zero;

            try
            {
                pPrimaryGroup = GetTokenInfo(token, Interop.TOKEN_INFORMATION_CLASS.TokenPrimaryGroup);
                Interop.TOKEN_PRIMARY_GROUP primaryGroup = (Interop.TOKEN_PRIMARY_GROUP)Marshal.PtrToStructure(pPrimaryGroup, typeof(Interop.TOKEN_PRIMARY_GROUP));

                if (primaryGroup.PrimaryGroup == IntPtr.Zero)
                {
                    return null;
                }

                return new SecurityIdentifier(primaryGroup.PrimaryGroup);
            }
            finally
            {
                if (pPrimaryGroup != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pPrimaryGroup);
                }
            }
        }

        public static IntPtr GetTokenInfo(IntPtr token, Interop.TOKEN_INFORMATION_CLASS informationClass)
        {
            // Wrapper that uses GetTokenInformation to retrieve the specified TOKEN_INFORMATION_CLASS

            var TokenInfLength = 0;

            // first call gets length of TokenInformation
            var Result = Interop.GetTokenInformation(token, informationClass, IntPtr.Zero, TokenInfLength, out TokenInfLength);
            var TokenInformation = Marshal.AllocHGlobal(TokenInfLength);
            Result = Interop.GetTokenInformation(token, informationClass, TokenInformation, TokenInfLength, out TokenInfLength);

            if (!Result)
            {
                Marshal.FreeHGlobal(TokenInformation);
                throw new Exception("Unable to get token info.");
            }

            return TokenInformation;
        }

        public static bool IsDomainSid(string sid)
        {
            // Returns true if the SID string matches a domain SID pattern

            string pattern = @"^S-1-[0-59]-\d{2}-\d{8,10}-\d{8,10}-\d{8,10}-[1-9]\d{2}";
            Match m = Regex.Match(sid, pattern, RegexOptions.IgnoreCase);
            return m.Success;
        }

        public static bool IsHighIntegrity()
        {
            // Returns true if the current process is running with administrative privs in a high integrity context

            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static bool GetSystem()
        {
            // helper to elevate to SYSTEM so we can get SeTcbPrivilege

            if (IsHighIntegrity())
            {
                IntPtr hToken = IntPtr.Zero;

                // Open winlogon's token with TOKEN_DUPLICATE accesss so we can make a copy of the token with DuplicateToken
                Process[] processes = Process.GetProcessesByName("winlogon");
                IntPtr handle = processes[0].Handle;

                // TOKEN_DUPLICATE = 0x0002
                bool success = Interop.OpenProcessToken(handle, 0x0002, out hToken);
                if (!success)
                {
                    Console.WriteLine("  [!] GetSystem() - OpenProcessToken failed!");
                    return false;
                }

                // make a copy of the NT AUTHORITY\SYSTEM token from winlogon
                // 2 == SecurityImpersonation
                IntPtr hDupToken = IntPtr.Zero;
                success = Interop.DuplicateToken(hToken, 2, ref hDupToken);
                if (!success)
                {
                    Interop.CloseHandle(hToken);
                    Console.WriteLine("  [!] GetSystem() - DuplicateToken failed!");
                    return false;
                }

                success = Interop.ImpersonateLoggedOnUser(hDupToken);
                if (!success)
                {
                    Interop.CloseHandle(hToken);
                    Interop.CloseHandle(hDupToken);
                    Console.WriteLine("  [!] GetSystem() - ImpersonateLoggedOnUser failed!");
                    return false;
                }

                // clean up the handles we created
                Interop.CloseHandle(hToken);
                Interop.CloseHandle(hDupToken);

                if (!IsSystem())
                {
                    return false;
                }

                return true;
            }
            else
            {
                return false;
            }
        }

        public static bool IsSystem()
        {
            // Returns true if the current context is "NT AUTHORITY\SYSTEM"

            var currentSid = WindowsIdentity.GetCurrent().User;
            return currentSid.IsWellKnown(WellKnownSidType.LocalSystemSid);
        }
    }
}
