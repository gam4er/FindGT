using System;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Security.Principal;

namespace FindGT.Membership
{
    /// <summary>
    /// Fallback provider: authoritative membership via a recursive LDAP/AD group walk.
    /// Recursion is cycle-protected (visited set) and depth-capped; on overflow it returns
    /// partial results with a warning rather than failing.
    /// (Logic moved out of FindGT.cs.)
    /// </summary>
    public class LdapMembershipProvider : IMembershipProvider
    {
        private const int MaxDepth = 64;

        public string Name { get { return "LDAP"; } }

        public MembershipResult GetExpectedGroups(MembershipQuery q, Action<string> log)
        {
            var result = new MembershipResult { Source = Name };

            if (q == null || q.UserSid == null || string.IsNullOrWhiteSpace(q.DnsDomain))
            {
                result.Error = "missing user SID or domain";
                return result;
            }

            try
            {
                var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                GetGroups(q.UserSid, dict, q.DnsDomain, 0, null, log);
                foreach (var kv in dict)
                {
                    if (kv.Key.StartsWith("S-1-5-21-"))
                    {
                        result.DomainGroupSids.Add(kv.Key);
                        result.SidToName[kv.Key] = kv.Value;
                    }
                }
                result.Success = true;
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }
            return result;
        }

        private static void GetGroups(SecurityIdentifier sid, Dictionary<string, string> groupMemberships,
            string domainName, int depth, HashSet<string> visited, Action<string> log)
        {
            try
            {
                if (sid == null || groupMemberships == null || string.IsNullOrWhiteSpace(domainName))
                    return;

                if (depth >= MaxDepth)
                {
                    if (log != null) log("[!] LDAP recursion depth limit reached for " + sid + "; returning partial results.");
                    return;
                }

                if (visited == null)
                    visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                if (!visited.Add(sid.Value))
                    return;

                using (PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, domainName))
                {
                    Principal p = Principal.FindByIdentity(principalContext, IdentityType.Sid, sid.ToString());
                    if (p != null)
                    {
                        PrincipalSearchResult<Principal> groups = p.GetGroups();
                        foreach (Principal group in groups)
                        {
                            if (group == null || group.Sid == null || groupMemberships.ContainsKey(group.Sid.Value))
                                continue;

                            try
                            {
                                DirectoryEntry de = (DirectoryEntry)group.GetUnderlyingObject();
                                PropertyCollection props = de.Properties;
                                var groupType = (int)props["groupType"].Value;
                                BitArray bits = new BitArray(BitConverter.GetBytes(groupType));
                                if (!bits[31])   // bit 31 => security group; skip distribution groups
                                    continue;
                            }
                            catch { }

                            if (group.Sid.Value.StartsWith("S-1-5-21-") && group.Context.ContextType != ContextType.Machine)
                            {
                                groupMemberships.Add(group.Sid.Value, group.Name);
                                GetGroups(group.Sid, groupMemberships, group.Context.Name, depth + 1, visited, log);
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                if (log != null) log("LDAP error: " + e.Message);
            }
        }
    }
}
