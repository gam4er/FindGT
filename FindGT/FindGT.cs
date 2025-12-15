using System;
using System.Collections.Generic;
using System.Linq;
using System.DirectoryServices.AccountManagement;
using System.Security.Principal;
using System.DirectoryServices.ActiveDirectory;
using System.Security.Cryptography;
using System.DirectoryServices;
using System.Collections;
using System.Runtime.InteropServices;
using System.Text;

namespace FindGT
{
    public static class FindGT
    {
        static void GetGroups(SecurityIdentifier sid, Dictionary<string, string> groupMemberships, string domainName)
        {
            try
            {
                PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, domainName);
                // Find the user by SID
                Principal P = Principal.FindByIdentity(principalContext, IdentityType.Sid, sid.ToString());

                if (P != null)
                {
                    PrincipalSearchResult<Principal> groups = P.GetGroups();

                    // Enumerate groups
                    foreach (Principal group in groups)
                    {
                        if (groupMemberships.Contains(new KeyValuePair<string, string>(group.Sid.ToString(),group.Name )))
                            continue;
                        
                        try
                        {
                            DirectoryEntry t = (DirectoryEntry)group.GetUnderlyingObject();
                            PropertyCollection PropColl = t.Properties;
                            var groupType = (int)PropColl["groupType"].Value;
                            BitArray bits = new BitArray(System.BitConverter.GetBytes(groupType));
                            if (!bits[31])
                                continue;
                        }
                        catch (Exception ex) { }


                        if (group.Sid.ToString().StartsWith("S-1-5-21-") && 
                            group.Context.ContextType != ContextType.Machine 
                            )
                        {
                            // Add group name and SID to the list
                            groupMemberships.Add(group.Sid.ToString(), group.Name);

                            // Recursive call for nested groups
                            GetGroups(group.Sid, groupMemberships, group.Context.Name);
                        }

                        if (group.Context.ContextType == ContextType.Machine)
                        {
                            Console.WriteLine("Machine");
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error: {e.Message}");
            }
        }

        static void Main(string[] args)
        {

            if (!Helpers.IsHighIntegrity())
            {
                Console.WriteLine("  [X] Not high integrity!");
                return;
            }

            if (Helpers.IsSystem())
            {
                Console.WriteLine("  [*] Already SYSTEM, not elevating\n");
            }
            else
            {
                if (!Helpers.GetSystem())
                {
                    Console.WriteLine("  [X] Error elevating to SYSTEM!");
                    return;
                }
                Console.WriteLine("  [*] Elevated to SYSTEM\n");
            }

            Dictionary<string, Find.FoundSession> logonSessions = Find.LogonSessions(true);

            string accountName = System.Environment.MachineName;
            string MachineSIDString = "";
            byte[] Sid = null;
            uint cbSid = 0;
            StringBuilder referencedDomainName = new StringBuilder();
            uint cchReferencedDomainName = (uint)referencedDomainName.Capacity;
            Interop.SID_NAME_USE sidUse;

            int err = Interop.NO_ERROR;
            if (!Interop.LookupAccountName(null, accountName, Sid, ref cbSid, referencedDomainName, ref cchReferencedDomainName, out sidUse))
            {
                err = Marshal.GetLastWin32Error();
                if (err == Interop.ERROR_INSUFFICIENT_BUFFER || err == Interop.ERROR_INVALID_FLAGS)
                {
                    Sid = new byte[cbSid];
                    referencedDomainName.EnsureCapacity((int)cchReferencedDomainName);
                    err = Interop.NO_ERROR;
                    if (!Interop.LookupAccountName(null, accountName, Sid, ref cbSid, referencedDomainName, ref cchReferencedDomainName, out sidUse))
                        err = Marshal.GetLastWin32Error();
                }
            }

            if (err == 0)
            {
                IntPtr ptrSid;
                if (!Interop.ConvertSidToStringSid(Sid, out ptrSid))
                {
                    err = Marshal.GetLastWin32Error();
                    //Console.WriteLine(@"Could not convert sid to string. Error : {0}", err);
                }
                else
                {
                    MachineSIDString = Marshal.PtrToStringAuto(ptrSid);
                    Interop.LocalFree(ptrSid);
                    //Console.WriteLine(@"Found sid {0} : {1}", sidUse, sidString);
                }
            }
            else
                Console.WriteLine(@"Error : {0}", err);

            string domainDnsName = null;
            string domainControllerName = null;
            PrincipalContext principalContext = null;

            try
            {
                Domain computerDomain = Domain.GetComputerDomain();
                domainDnsName = computerDomain.Name;
                DomainController domainController = computerDomain.FindDomainController();
                domainControllerName = domainController.Name;
                principalContext = new PrincipalContext(ContextType.Domain, domainDnsName);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  [!] Unable to resolve domain controller information: {ex.Message}");
            }

            foreach (var session in logonSessions.Where(s => s.Value.AuthPackage == "Kerberos").ToList())
            {
                ulong luid = 0;
                ulong.TryParse(session.Value.Luid, out luid);
                LUID userLuid = new LUID(luid);
                IntPtr hToken = Creds.NegotiateToken(userLuid, null, true);
                string sidString = session.Value.SID;
                SecurityIdentifier sid = new SecurityIdentifier(sidString);

                List<string> groupSids = Helpers.GetTokenGroups(hToken)
                    .Where(g => g.StartsWith("S-1-5-21-") && g != "S-1-5-21-0-0-0-497" && !g.StartsWith(MachineSIDString))
                    .ToList();

                if (principalContext != null)
                {
                    foreach (var group in groupSids)
                    {
                        try
                        {
                            Principal foundPrincipal = Principal.FindByIdentity(principalContext, IdentityType.Sid, group);

                            if (foundPrincipal is UserPrincipal)
                            {
                                Console.WriteLine($"Token on User {sid} in Session {string.Format("0x{0:X}", luid)}\nContains object with SID {group} that is a User.");
                            }
                            else if (foundPrincipal == null)
                            {
                                Console.WriteLine($"Token on User {sid} in Session {string.Format("0x{0:X}", luid)}\nContains object with SID {group} that could not be resolved.");
                            }
                        }
                        catch (Exception lookupEx)
                        {
                            Console.WriteLine($"  [!] Failed to resolve SID {group}: {lookupEx.Message}");
                        }
                    }
                }

                HashSet<string> netlogonGroupSids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                try
                {
                    string userDomainNetbios = null;
                    string sessionUserName = session.Value.UserName ?? string.Empty;
                    int separatorIndex = sessionUserName.IndexOf('\\');
                    if (separatorIndex >= 0)
                    {
                        userDomainNetbios = sessionUserName.Substring(0, separatorIndex);
                    }

                    NetlogonValidationSamInfo validationInfo = NetlogonHelper.GetValidationSamInfo(
                        sid,
                        session.Value.UserName,
                        userDomainNetbios,
                        domainDnsName,
                        domainControllerName);

                    if (validationInfo != null)
                    {
                        if (validationInfo.LogonDomainId != null && validationInfo.GroupIds != null)
                        {
                            string domainSidValue = validationInfo.LogonDomainId.Value;
                            foreach (var membership in validationInfo.GroupIds)
                            {
                                try
                                {
                                    SecurityIdentifier groupSid = new SecurityIdentifier(domainSidValue + "-" + membership.RelativeId);
                                    netlogonGroupSids.Add(groupSid.Value);
                                }
                                catch (Exception buildEx)
                                {
                                    Console.WriteLine($"  [!] Failed to build SID for RID {membership.RelativeId}: {buildEx.Message}");
                                }
                            }
                        }

                        if (validationInfo.ExtraSids != null)
                        {
                            foreach (var extra in validationInfo.ExtraSids)
                            {
                                if (extra.Sid != null)
                                {
                                    netlogonGroupSids.Add(extra.Sid.Value);
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  [!] Netlogon lookup failed for {session.Value.UserName}: {ex.Message}");
                }

                Console.WriteLine("Token on User {0} in Session {1} contains {2} groups", sid, string.Format("0x{0:X}", luid), groupSids.Count);
                Console.WriteLine("Netlogon reports {0} groups for {1}", netlogonGroupSids.Count, sid);

                foreach (var group in groupSids)
                {
                    if (!netlogonGroupSids.Contains(group))
                    {
                        Console.WriteLine("Token on User {0} in Session {1} contains {2} but Netlogon membership does not", sid, string.Format("0x{0:X}", luid), group);
                    }
                }

                foreach (var groupSid in netlogonGroupSids)
                {
                    if (!groupSids.Contains(groupSid))
                    {
                        Console.WriteLine("Token on User {0} in Session {1} doesn't contain {2} but Netlogon membership includes it", sid, string.Format("0x{0:X}", luid), groupSid);
                    }
                }
            }

            principalContext?.Dispose();
        }
    }
}
