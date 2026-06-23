using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using FindGT.Membership;
using FindGT.Reporting;

namespace FindGT.Cli
{
    /// <summary>Orchestrates the membership scan: elevation + per-session token-vs-authoritative diff.</summary>
    internal static class AppRunner
    {
        /// <summary>Ensures the process runs as SYSTEM (needed for S4U logon and token access).</summary>
        public static bool EnsureSystem()
        {
            if (!Helpers.IsHighIntegrity())
            {
                Ui.Error("Требуется запуск от администратора (high integrity).");
                return false;
            }
            if (Helpers.IsSystem())
            {
                Ui.Info("Уже SYSTEM — эскалация не требуется.");
                return true;
            }
            if (!Helpers.GetSystem())
            {
                Ui.Error("Не удалось повысить привилегии до SYSTEM.");
                return false;
            }
            Ui.Success("Повышены привилегии до SYSTEM.");
            return true;
        }

        public static int RunReport(bool verbose, bool html)
        {
            Dictionary<string, Find.FoundSession> logonSessions = Find.LogonSessions(false);

            string machineSidString = GetMachineSid();

            string domainDnsName = null;
            try { domainDnsName = Domain.GetComputerDomain().Name; }
            catch (Exception ex) { Ui.Warn("Не удалось определить домен: " + ex.Message); }

            var s4uProvider = new S4UMembershipProvider();
            var ldapProvider = new LdapMembershipProvider();
            var reporter = new SpectreReporter(verbose, html);
            reporter.Header();
            Action<string> noLog = delegate { };

            foreach (var session in logonSessions.Where(s => s.Value.AuthPackage == "Kerberos").ToList())
            {
                ulong luid = 0;
                ulong.TryParse(session.Value.Luid, out luid);
                LUID userLuid = new LUID(luid);
                IntPtr hToken = Creds.NegotiateToken(userLuid, null, false);
                string sidString = session.Value.SID;
                SecurityIdentifier sid = new SecurityIdentifier(sidString);

                var tokenGroups = new HashSet<string>(
                    Helpers.GetTokenGroups(hToken)
                        .Where(g => IsComparableDomainSid(g, machineSidString)),
                    StringComparer.OrdinalIgnoreCase);

                if (hToken != IntPtr.Zero)
                    Interop.CloseHandle(hToken);

                string userName = session.Value.UserName ?? string.Empty;
                string sam = userName.Contains("\\") ? userName.Substring(userName.LastIndexOf('\\') + 1) : userName;
                var query = new MembershipQuery
                {
                    UserSid = sid,
                    SamAccountName = sam,
                    Upn = (!string.IsNullOrEmpty(sam) && !string.IsNullOrEmpty(domainDnsName)) ? sam + "@" + domainDnsName : null,
                    Nt4Name = userName.Contains("\\") ? userName : null,
                    DnsDomain = domainDnsName
                };

                var reference = s4uProvider.GetExpectedGroups(query, noLog);
                if (!reference.Success)
                {
                    var ldap = ldapProvider.GetExpectedGroups(query, noLog);
                    if (ldap.Success)
                        reference = ldap;
                }

                var refGroups = new HashSet<string>(
                    reference.DomainGroupSids.Where(g => IsComparableDomainSid(g, machineSidString)),
                    StringComparer.OrdinalIgnoreCase);

                var rows = MembershipComparer.Compare(tokenGroups, refGroups, verbose);
                MembershipComparer.Enrich(rows);

                reporter.RenderSession(new SessionReport
                {
                    Luid = string.Format("0x{0:X}", luid),
                    UserSid = sidString,
                    UserName = userName,
                    AuthPackage = session.Value.AuthPackage,
                    ReferenceSource = reference.Source,
                    ReferenceOk = reference.Success,
                    ReferenceError = reference.Error,
                    TokenDomainGroupCount = tokenGroups.Count,
                    ReferenceDomainGroupCount = refGroups.Count,
                    Rows = rows
                });
            }

            reporter.Finish();
            return 0;
        }

        /// <summary>Domain group SID that is relevant to forged-membership detection (excludes the
        /// Claims-Valid pseudo-SID and the machine's own SID).</summary>
        private static bool IsComparableDomainSid(string sid, string machineSidString)
        {
            if (string.IsNullOrEmpty(sid) || !sid.StartsWith("S-1-5-21-"))
                return false;
            if (sid == "S-1-5-21-0-0-0-497")
                return false;
            if (!string.IsNullOrEmpty(machineSidString) && sid.StartsWith(machineSidString))
                return false;
            return true;
        }

        private static string GetMachineSid()
        {
            string accountName = Environment.MachineName;
            byte[] sidBytes = null;
            uint cbSid = 0;
            var referencedDomain = new StringBuilder();
            uint cchReferenced = (uint)referencedDomain.Capacity;
            Interop.SID_NAME_USE sidUse;

            int err = Interop.NO_ERROR;
            if (!Interop.LookupAccountName(null, accountName, sidBytes, ref cbSid, referencedDomain, ref cchReferenced, out sidUse))
            {
                err = Marshal.GetLastWin32Error();
                if (err == Interop.ERROR_INSUFFICIENT_BUFFER || err == Interop.ERROR_INVALID_FLAGS)
                {
                    sidBytes = new byte[cbSid];
                    referencedDomain.EnsureCapacity((int)cchReferenced);
                    err = Interop.NO_ERROR;
                    if (!Interop.LookupAccountName(null, accountName, sidBytes, ref cbSid, referencedDomain, ref cchReferenced, out sidUse))
                        err = Marshal.GetLastWin32Error();
                }
            }

            if (err == 0 && sidBytes != null)
            {
                IntPtr ptrSid;
                if (Interop.ConvertSidToStringSid(sidBytes, out ptrSid))
                {
                    string s = Marshal.PtrToStringAuto(ptrSid);
                    Interop.LocalFree(ptrSid);
                    return s ?? string.Empty;
                }
            }
            return string.Empty;
        }
    }
}
