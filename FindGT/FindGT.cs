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
using System.Diagnostics;
using CommandLine;

namespace FindGT
{
    public static class FindGT
    {
        // Class to define command line options
        public class Options
        {
            [Option("console", Default = false, HelpText = "Output session information to console.")]
            public bool ConsoleOutput { get; set; }
        }

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

        /// <summary>
        /// Метод для записи в журнал событий Windows
        /// </summary>
        /// <param name="message">Сообщение</param>
        /// <param name="entryType">Тип записи</param>
        static void WriteToEventLog(string message, EventLogEntryType entryType)
        {
            string source = "FindGT";
            string log = "Application";

            if (!EventLog.SourceExists(source))
            {
                EventLog.CreateEventSource(source, log);
            }

            using (EventLog eventLog = new EventLog(log))
            {
                eventLog.Source = source;
                eventLog.WriteEntry(message, entryType);
            }
        }

        static void Main(string [] args)
        {
            Parser.Default.ParseArguments<Options>(args)
                .WithParsed(options => Run(options))
                .WithNotParsed(errors =>
                {
                    Console.WriteLine("Invalid arguments provided.");
                });
        }

        private static void Run(Options options)
        {
            if (!Helpers.IsHighIntegrity())
            {
                if (options.ConsoleOutput)
                    Console.WriteLine("  [X] Not high integrity!");
                return;
            }

            if (Helpers.IsSystem())
            {
                if (options.ConsoleOutput)
                    Console.WriteLine("  [*] Already SYSTEM, not elevating\n");
            }
            else
            {
                if (!Helpers.GetSystem())
                {
                    if (options.ConsoleOutput)
                        Console.WriteLine("  [X] Error elevating to SYSTEM!");
                    return;
                }
                if (options.ConsoleOutput)
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
                if (options.ConsoleOutput)
                    Console.WriteLine(@"Error : {0}", err);

            foreach (var session in logonSessions.Where(s => s.Value.AuthPackage == "Kerberos").ToList())
            {
                ulong luid = 0;
                ulong.TryParse(session.Value.Luid, out luid);
                LUID userLuid = new LUID(luid);
                IntPtr hToken = Creds.NegotiateToken(userLuid, null, true);
                Dictionary<string, string> groupMembership = new Dictionary<string, string>();
                string sidString = session.Value.SID;
                SecurityIdentifier sid = new SecurityIdentifier(sidString);
                StringBuilder sb = new StringBuilder();
                var logLevel = EventLogEntryType.Information;

                List<string> groupSids = Helpers.GetTokenGroups(hToken).Where(g => g.StartsWith("S-1-5-21-") && g != "S-1-5-21-0-0-0-497" && !g.StartsWith(MachineSIDString)).ToList();

                PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, Domain.GetComputerDomain().Name);
                foreach (var group in groupSids)
                {
                    Principal foundPrincipal = Principal.FindByIdentity(principalContext, IdentityType.Sid, group);

                    if (foundPrincipal is GroupPrincipal)
                    {
                        //Console.WriteLine($"The object with SID {sidToCheck} is a Group.");
                    }
                    else if (foundPrincipal is UserPrincipal)
                    {
                        if (options.ConsoleOutput)
                            Console.WriteLine($"Token on User {sid} in Session {string.Format("0x{0:X}", luid)}\nContains object with SID {group} that is a User.");
                        sb.Append(String.Format($"Token on User {sid} in Session {string.Format("0x{0:X}", luid)}\nContains object with SID {group} that is a User.\n"));
                    }
                    else
                    {
                        if (options.ConsoleOutput)
                            Console.WriteLine($"Token on User {sid} in Session {string.Format("0x{0:X}", luid)}\nContains object with SID {group} of some type or does not exist.");
                        sb.Append(String.Format($"Token on User {sid} in Session {string.Format("0x{0:X}", luid)}\nContains object with SID {group} of some type or does not exist.\n"));
                    }
                }

                try
                {
                    GetGroups(sid, groupMembership, Domain.GetComputerDomain().Name);
                }
                catch (Exception ex)
                {
                    if (options.ConsoleOutput)
                        Console.WriteLine($"An error occurred: {ex.Message}");
                }
                if (options.ConsoleOutput)
                {
                    Console.WriteLine("Token on User {0} in Session {1} contains {2} groups", sid, string.Format("0x{0:X}", luid), groupSids.Count);
                    Console.WriteLine("IRL User {0} belongs to {2} groups", sid, string.Format("0x{0:X}", luid), groupMembership.Count);
                }

                sb.Append(String.Format("Token on User {0} in Session {1} contains {2} groups\n", sid, string.Format("0x{0:X}", luid), groupSids.Count));
                sb.Append(String.Format("IRL User {0} belongs to {2} groups\n", sid, string.Format("0x{0:X}", luid), groupMembership.Count));

                foreach (var group in groupSids)
                    if (!groupMembership.ContainsKey(group))
                    {
                        if (options.ConsoleOutput)
                        {
                            Console.WriteLine("Token on User {0} in Session {1} contains {2} but doesn't", sid, string.Format("0x{0:X}", luid), group);
                        }
                        sb.Append(String.Format("Token on User {0} in Session {1} contains {2} but doesn't\n", sid, string.Format("0x{0:X}", luid), group));

                        logLevel = EventLogEntryType.Warning;
                    }

                foreach (var group in groupMembership)
                    if (!groupSids.Contains(group.Key))
                    {
                        if (options.ConsoleOutput)
                        {
                            Console.WriteLine("Token on User {0} in Session {1} doesn't contains {2} but should", sid, string.Format("0x{0:X}", luid), group.Key);
                        }
                        sb.Append(String.Format("Token on User {0} in Session {1} doesn't contains {2} but should\n", sid, string.Format("0x{0:X}", luid), group.Key));
                        logLevel = EventLogEntryType.Warning;
                    }

                WriteToEventLog(sb.ToString(), logLevel);
            }
        }
    }
}
