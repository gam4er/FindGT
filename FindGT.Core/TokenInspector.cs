using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace FindGT
{
    public static class TokenInspector
    {
        public struct TokenGroup
        {
            public SecurityIdentifier Sid;
            public uint Attributes;
        }

        public static List<string> GetTokenGroups(IntPtr token)
        {
            List<TokenGroup> groups = GetTokenGroupsWithAttributes(token);
            List<string> groupSids = new List<string>(groups.Count);
            foreach (TokenGroup group in groups)
            {
                groupSids.Add(group.Sid.Value);
            }

            return groupSids;
        }

        public static List<TokenGroup> GetTokenGroupsWithAttributes(IntPtr token)
        {
            List<TokenGroup> groups = new List<TokenGroup>();
            using (SafeHGlobalBuffer buffer = GetTokenInformationBuffer(
                token,
                Interop.TOKEN_INFORMATION_CLASS.TokenGroups))
            {
                IntPtr basePointer = buffer.DangerousGetHandle();
                Interop.TOKEN_GROUPS tokenGroups =
                    (Interop.TOKEN_GROUPS)Marshal.PtrToStructure(
                        basePointer,
                        typeof(Interop.TOKEN_GROUPS));

                int entrySize = Marshal.SizeOf(typeof(Interop.SID_AND_ATTRIBUTES));
                long firstEntryOffset = Marshal.OffsetOf(
                    typeof(Interop.TOKEN_GROUPS),
                    "Groups").ToInt64();

                for (uint index = 0; index < tokenGroups.GroupCount; index++)
                {
                    long entryOffset = checked(firstEntryOffset + ((long)entrySize * index));
                    IntPtr entryPointer = new IntPtr(
                        checked(basePointer.ToInt64() + entryOffset));
                    Interop.SID_AND_ATTRIBUTES entry =
                        (Interop.SID_AND_ATTRIBUTES)Marshal.PtrToStructure(
                            entryPointer,
                            typeof(Interop.SID_AND_ATTRIBUTES));

                    if (entry.Sid != IntPtr.Zero)
                    {
                        groups.Add(new TokenGroup
                        {
                            Sid = new SecurityIdentifier(entry.Sid),
                            Attributes = entry.Attributes
                        });
                    }
                }
            }

            return groups;
        }

        public static SecurityIdentifier GetTokenPrimaryGroup(IntPtr token)
        {
            using (SafeHGlobalBuffer buffer = GetTokenInformationBuffer(
                token,
                Interop.TOKEN_INFORMATION_CLASS.TokenPrimaryGroup))
            {
                Interop.TOKEN_PRIMARY_GROUP primaryGroup =
                    (Interop.TOKEN_PRIMARY_GROUP)Marshal.PtrToStructure(
                        buffer.DangerousGetHandle(),
                        typeof(Interop.TOKEN_PRIMARY_GROUP));

                return primaryGroup.PrimaryGroup == IntPtr.Zero
                    ? null
                    : new SecurityIdentifier(primaryGroup.PrimaryGroup);
            }
        }

        public static SecurityIdentifier GetTokenUser(IntPtr token)
        {
            using (SafeHGlobalBuffer buffer = GetTokenInformationBuffer(
                token,
                Interop.TOKEN_INFORMATION_CLASS.TokenUser))
            {
                Interop.TOKEN_USER user =
                    (Interop.TOKEN_USER)Marshal.PtrToStructure(
                        buffer.DangerousGetHandle(),
                        typeof(Interop.TOKEN_USER));
                if (user.User.Sid == IntPtr.Zero)
                {
                    throw new InvalidOperationException(
                        "The token does not contain a user SID.");
                }

                return new SecurityIdentifier(user.User.Sid);
            }
        }

        public static bool IsDomainSid(string sid)
        {
            if (String.IsNullOrWhiteSpace(sid))
            {
                return false;
            }

            try
            {
                SecurityIdentifier identifier = new SecurityIdentifier(sid);
                return identifier.AccountDomainSid != null &&
                    identifier.Value.StartsWith("S-1-5-21-", StringComparison.Ordinal);
            }
            catch (ArgumentException)
            {
                return false;
            }
        }

        private static SafeHGlobalBuffer GetTokenInformationBuffer(
            IntPtr token,
            Interop.TOKEN_INFORMATION_CLASS informationClass)
        {
            if (token == IntPtr.Zero)
            {
                throw new ArgumentException("A valid token handle is required.", "token");
            }

            int requiredLength;
            Interop.GetTokenInformation(
                token,
                informationClass,
                IntPtr.Zero,
                0,
                out requiredLength);

            int firstError = Marshal.GetLastWin32Error();
            if (requiredLength <= 0)
            {
                throw new Win32Exception(
                    firstError,
                    "GetTokenInformation did not report a required buffer size.");
            }

            SafeHGlobalBuffer buffer = SafeHGlobalBuffer.Allocate(requiredLength);
            bool success = Interop.GetTokenInformation(
                token,
                informationClass,
                buffer.DangerousGetHandle(),
                requiredLength,
                out requiredLength);

            if (success)
            {
                return buffer;
            }

            int error = Marshal.GetLastWin32Error();
            buffer.Dispose();
            throw new Win32Exception(error, "GetTokenInformation failed.");
        }
    }
}
