using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace FindGT.Membership
{
    public sealed class LdapMembershipProvider : IMembershipProvider
    {
        private const int MaximumDepth = 64;
        private const int SecurityEnabledGroupFlag = unchecked((int)0x80000000);

        public string Name
        {
            get { return "LDAP"; }
        }

        public MembershipResult GetExpectedGroups(MembershipQuery query, Action<string> log)
        {
            MembershipResult result = new MembershipResult { Source = Name };
            if (query == null ||
                query.UserSid == null ||
                String.IsNullOrWhiteSpace(query.DnsDomain))
            {
                result.Error = "Missing user SID or DNS domain.";
                return result;
            }

            try
            {
                Dictionary<string, string> memberships =
                    new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                HashSet<string> visited =
                    new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                using (PrincipalContext context =
                    new PrincipalContext(ContextType.Domain, query.DnsDomain))
                using (Principal principal = Principal.FindByIdentity(
                    context,
                    IdentityType.Sid,
                    query.UserSid.Value))
                {
                    if (principal == null)
                    {
                        result.AccountExists = false;
                        result.Success = true;
                        return result;
                    }

                    result.AccountExists = true;
                    result.ResolvedUserSid = principal.Sid == null
                        ? null
                        : principal.Sid.Value;
                    result.ResolvedSamAccountName = principal.SamAccountName;

                    AuthenticablePrincipal authenticable =
                        principal as AuthenticablePrincipal;
                    if (authenticable != null)
                    {
                        result.AccountEnabled = authenticable.Enabled;
                    }

                    using (DirectoryEntry entry =
                        (DirectoryEntry)principal.GetUnderlyingObject())
                    {
                        PropertyValueCollection sidHistory =
                            entry.Properties["sIDHistory"];
                        foreach (object rawSid in sidHistory)
                        {
                            byte[] binarySid = rawSid as byte[];
                            if (binarySid != null)
                            {
                                result.SidHistorySids.Add(
                                    new SecurityIdentifier(binarySid, 0).Value);
                            }
                        }
                    }
                }

                GetGroups(
                    query.UserSid,
                    memberships,
                    query.DnsDomain,
                    0,
                    visited);

                foreach (KeyValuePair<string, string> membership in memberships)
                {
                    if (membership.Key.StartsWith(
                        "S-1-5-21-",
                        StringComparison.Ordinal))
                    {
                        result.DomainGroupSids.Add(membership.Key);
                        result.SidToName[membership.Key] = membership.Value;
                    }
                }

                result.Success = true;
            }
            catch (PrincipalOperationException exception)
            {
                result.Error = exception.Message;
            }
            catch (DirectoryServicesCOMException exception)
            {
                result.Error = exception.Message;
            }
            catch (COMException exception)
            {
                result.Error = exception.Message;
            }
            catch (UnauthorizedAccessException exception)
            {
                result.Error = exception.Message;
            }
            catch (InvalidOperationException exception)
            {
                result.Error = exception.Message;
            }
            catch (ArgumentException exception)
            {
                result.Error = exception.Message;
            }

            if (!result.Success && log != null)
            {
                log("LDAP error: " + result.Error);
            }

            return result;
        }

        private static void GetGroups(
            SecurityIdentifier sid,
            IDictionary<string, string> memberships,
            string domainName,
            int depth,
            ISet<string> visited)
        {
            if (depth >= MaximumDepth)
            {
                throw new InvalidOperationException(
                    "LDAP group recursion exceeded the depth limit of " +
                    MaximumDepth.ToString(CultureInfo.InvariantCulture) + ".");
            }

            if (!visited.Add(sid.Value))
            {
                return;
            }

            using (PrincipalContext context =
                new PrincipalContext(ContextType.Domain, domainName))
            using (Principal principal = Principal.FindByIdentity(
                context,
                IdentityType.Sid,
                sid.Value))
            {
                if (principal == null)
                {
                    throw new InvalidOperationException(
                        "Account " + sid.Value +
                        " could not be resolved through domain " + domainName + ".");
                }

                using (PrincipalSearchResult<Principal> groups = principal.GetGroups())
                {
                    foreach (Principal group in groups)
                    {
                        using (group)
                        {
                            if (group == null || group.Sid == null)
                            {
                                throw new InvalidOperationException(
                                    "LDAP returned a group without a SID.");
                            }

                            string groupSid = group.Sid.Value;
                            if (memberships.ContainsKey(groupSid))
                            {
                                continue;
                            }

                            using (DirectoryEntry entry =
                                (DirectoryEntry)group.GetUnderlyingObject())
                            {
                                object rawGroupType =
                                    entry.Properties["groupType"].Value;
                                if (rawGroupType == null)
                                {
                                    throw new InvalidOperationException(
                                        "LDAP group " + groupSid +
                                        " does not expose groupType.");
                                }

                                int groupType = Convert.ToInt32(
                                    rawGroupType,
                                    CultureInfo.InvariantCulture);
                                if ((groupType & SecurityEnabledGroupFlag) == 0)
                                {
                                    continue;
                                }
                            }

                            if (!groupSid.StartsWith(
                                "S-1-5-21-",
                                StringComparison.Ordinal))
                            {
                                continue;
                            }

                            if (group.Context == null ||
                                group.Context.ContextType == ContextType.Machine)
                            {
                                continue;
                            }

                            memberships.Add(
                                groupSid,
                                String.IsNullOrWhiteSpace(group.Name)
                                    ? groupSid
                                    : group.Name);

                            string groupDomain = String.IsNullOrWhiteSpace(
                                group.Context.Name)
                                ? domainName
                                : group.Context.Name;
                            GetGroups(
                                group.Sid,
                                memberships,
                                groupDomain,
                                depth + 1,
                                visited);
                        }
                    }
                }
            }
        }
    }
}
