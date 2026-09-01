using System;
using System.Collections.Generic;
using System.Linq;
using FindGT.Core;
using FindGT.Core.Analysis;
using FindGT.Membership;

namespace FindGT.Tests
{
    internal static class TestFixtures
    {
        internal const string DomainSid =
            "S-1-5-21-1111111111-2222222222-3333333333";
        internal const string OtherDomainSid =
            "S-1-5-21-4444444444-5555555555-6666666666";
        internal const string UserSid = DomainSid + "-1100";
        internal const string DomainUsersSid = DomainSid + "-513";
        internal const string DomainAdminsSid = DomainSid + "-512";

        internal static LogonSessionSnapshot Session(ulong logonId)
        {
            return new LogonSessionSnapshot
            {
                LogonId = new LUID(logonId),
                UserName = "CONTOSO\\testuser",
                AccountName = "testuser",
                LogonDomain = "CONTOSO",
                DnsDomainName = "CONTOSO.COM",
                Upn = "testuser@CONTOSO.COM",
                UserSid = UserSid,
                LogonType = 3,
                AuthenticationPackage = "Kerberos"
            };
        }

        internal static MembershipResult Reference(params string[] groups)
        {
            MembershipResult result = new MembershipResult
            {
                Source = "TestReference",
                Success = true,
                AccountExists = true,
                AccountEnabled = true,
                ResolvedUserSid = UserSid,
                ResolvedSamAccountName = "testuser"
            };
            foreach (string group in groups)
            {
                result.DomainGroupSids.Add(group);
            }

            return result;
        }
    }

    internal sealed class FakeSessionDataSource : ISessionDataSource
    {
        internal IDictionary<LUID, LogonSessionSnapshot> Sessions { get; } =
            new Dictionary<LUID, LogonSessionSnapshot>();
        internal IDictionary<LUID, IReadOnlyList<TokenGroupInfo>> Groups { get; } =
            new Dictionary<LUID, IReadOnlyList<TokenGroupInfo>>();
        internal Exception GroupFailure { get; set; }

        public LogonSessionSnapshot GetSession(LUID logonId)
        {
            LogonSessionSnapshot value;
            return Sessions.TryGetValue(logonId, out value) ? value : null;
        }

        public IReadOnlyCollection<LogonSessionSnapshot> EnumerateSessions()
        {
            return Sessions.Values.ToList().AsReadOnly();
        }

        public IReadOnlyList<TokenGroupInfo> GetTokenGroups(LUID logonId)
        {
            if (GroupFailure != null)
            {
                throw GroupFailure;
            }

            IReadOnlyList<TokenGroupInfo> value;
            return Groups.TryGetValue(logonId, out value)
                ? value
                : new List<TokenGroupInfo>().AsReadOnly();
        }
    }

    internal sealed class FakeReferenceResolver : IReferenceMembershipResolver
    {
        internal MembershipResult Result { get; set; }

        public MembershipResult Resolve(LogonSessionSnapshot session)
        {
            return Result;
        }
    }
}
