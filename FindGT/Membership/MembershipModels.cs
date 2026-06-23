using System;
using System.Collections.Generic;
using System.Security.Principal;

namespace FindGT.Membership
{
    /// <summary>Identity of the session whose authoritative membership we want to resolve.</summary>
    public class MembershipQuery
    {
        public SecurityIdentifier UserSid;
        public string SamAccountName;   // e.g. "rodchenko"
        public string Upn;              // e.g. "rodchenko@avp.ru"
        public string Nt4Name;          // e.g. "KL\\rodchenko"
        public string DnsDomain;        // e.g. "AVP.RU"
    }

    /// <summary>Authoritative (expected) membership computed by a provider.</summary>
    public class MembershipResult
    {
        public string Source;           // provider name, e.g. "S4U2Self" / "LDAP"
        public bool Success;
        public string Error;
        public HashSet<string> DomainGroupSids =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase);   // S-1-5-21-*
        public Dictionary<string, string> SidToName =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>A source of expected (authoritative) group membership for a domain user.</summary>
    public interface IMembershipProvider
    {
        string Name { get; }
        MembershipResult GetExpectedGroups(MembershipQuery query, Action<string> log);
    }
}
