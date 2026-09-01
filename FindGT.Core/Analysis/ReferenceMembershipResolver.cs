using System;
using FindGT.Membership;

namespace FindGT.Core.Analysis
{
    internal sealed class ReferenceMembershipResolver : IReferenceMembershipResolver
    {
        private readonly IMembershipProvider _s4uProvider;
        private readonly IMembershipProvider _ldapProvider;
        private readonly Action<string> _log;

        internal ReferenceMembershipResolver(Action<string> log)
            : this(new S4UMembershipProvider(), new LdapMembershipProvider(), log)
        {
        }

        internal ReferenceMembershipResolver(
            IMembershipProvider s4uProvider,
            IMembershipProvider ldapProvider,
            Action<string> log)
        {
            _s4uProvider = s4uProvider ??
                throw new ArgumentNullException("s4uProvider");
            _ldapProvider = ldapProvider ??
                throw new ArgumentNullException("ldapProvider");
            _log = log ?? delegate { };
        }

        public MembershipResult Resolve(LogonSessionSnapshot session)
        {
            if (session == null)
            {
                throw new ArgumentNullException("session");
            }

            string dnsDomain = ResolveDnsDomain(session);
            MembershipQuery query = new MembershipQuery
            {
                UserSid = new System.Security.Principal.SecurityIdentifier(
                    session.UserSid),
                SamAccountName = session.AccountName,
                Upn = !String.IsNullOrWhiteSpace(session.Upn)
                    ? session.Upn
                    : BuildUpn(session.AccountName, dnsDomain),
                Nt4Name = !String.IsNullOrWhiteSpace(session.LogonDomain) &&
                    !String.IsNullOrWhiteSpace(session.AccountName)
                    ? session.LogonDomain + "\\" + session.AccountName
                    : null,
                DnsDomain = dnsDomain
            };

            MembershipResult s4u = _s4uProvider.GetExpectedGroups(query, _log);
            if (s4u.Success)
            {
                return s4u;
            }

            MembershipResult ldap = _ldapProvider.GetExpectedGroups(query, _log);
            if (ldap.Success)
            {
                return ldap;
            }

            return new MembershipResult
            {
                Source = "S4U2Self/LDAP",
                Success = false,
                Error = "S4U2Self: " + (s4u.Error ?? "unknown failure") +
                    " | LDAP: " + (ldap.Error ?? "unknown failure")
            };
        }

        private static string BuildUpn(string accountName, string dnsDomain)
        {
            return String.IsNullOrWhiteSpace(accountName) ||
                String.IsNullOrWhiteSpace(dnsDomain)
                ? null
                : accountName + "@" + dnsDomain;
        }

        private static string ResolveDnsDomain(LogonSessionSnapshot session)
        {
            if (!String.IsNullOrWhiteSpace(session.DnsDomainName))
            {
                return session.DnsDomainName;
            }

            if (!String.IsNullOrWhiteSpace(session.Upn))
            {
                int separator = session.Upn.LastIndexOf('@');
                if (separator >= 0 && separator < session.Upn.Length - 1)
                {
                    return session.Upn.Substring(separator + 1);
                }
            }

            return null;
        }
    }
}
