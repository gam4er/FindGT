using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace FindGT.Membership
{
    /// <summary>Resolves a SID to a friendly name and its account type (user vs group, etc.).</summary>
    public static class SidUtil
    {
        private enum SID_NAME_USE
        {
            SidTypeUser = 1,
            SidTypeGroup = 2,
            SidTypeDomain = 3,
            SidTypeAlias = 4,
            SidTypeWellKnownGroup = 5,
            SidTypeDeletedAccount = 6,
            SidTypeInvalid = 7,
            SidTypeUnknown = 8,
            SidTypeComputer = 9
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LookupAccountSid(
            string lpSystemName,
            byte[] Sid,
            StringBuilder lpName,
            ref uint cchName,
            StringBuilder lpReferencedDomainName,
            ref uint cchReferencedDomainName,
            out int peUse);

        /// <summary>
        /// Resolves the SID. Sets <paramref name="name"/> to DOMAIN\name (best effort) and
        /// <paramref name="isUser"/> true if the SID is a user/computer account rather than a group.
        /// </summary>
        public static void Classify(string sidString, out string name, out bool isUser)
        {
            name = null;
            isUser = false;
            try
            {
                var sid = new SecurityIdentifier(sidString);
                byte[] binary = new byte[sid.BinaryLength];
                sid.GetBinaryForm(binary, 0);

                var nameSb = new StringBuilder(256);
                var domainSb = new StringBuilder(256);
                uint cchName = (uint)nameSb.Capacity;
                uint cchDomain = (uint)domainSb.Capacity;
                int use;

                if (LookupAccountSid(null, binary, nameSb, ref cchName, domainSb, ref cchDomain, out use))
                {
                    string domain = domainSb.ToString();
                    string n = nameSb.ToString();
                    name = string.IsNullOrEmpty(domain) ? n : domain + "\\" + n;
                    isUser = use == (int)SID_NAME_USE.SidTypeUser || use == (int)SID_NAME_USE.SidTypeComputer;
                }
            }
            catch
            {
                // leave name null / isUser false
            }
        }

        public static string ResolveName(string sidString)
        {
            string name;
            bool isUser;
            Classify(sidString, out name, out isUser);
            return name;
        }
    }
}
