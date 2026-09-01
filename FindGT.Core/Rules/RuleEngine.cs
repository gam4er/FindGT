using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using FindGT.Membership;

namespace FindGT.Core.Rules
{
    public static class RuleEngine
    {
        private const uint SeGroupEnabled = 0x00000004;
        private const uint SeGroupUseForDenyOnly = 0x00000010;

        public const string TokenGroupNotInAuthoritativeMembership = "FGT001";
        public const string AuthoritativeGroupMissingFromToken = "FGT002";
        public const string UserSidPresentInGroupList = "FGT003";
        public const string UserNameSidMismatch = "FGT004";
        public const string AccountDoesNotExist = "FGT005";
        public const string AccountDisabled = "FGT006";
        public const string SuspiciousSidHistory = "FGT007";
        public const string TokenGroupAttributeMismatch = "FGT008";
        public const string CrossDomainMembershipInconsistency = "FGT009";
        public const string EventVsLsaIdentityMismatch = "FGT010";

        public static IList<GroupComparison> BuildComparisons(
            LogonSessionSnapshot session,
            IEnumerable<TokenGroupInfo> tokenGroups,
            MembershipResult reference)
        {
            if (session == null)
                throw new ArgumentNullException("session");
            if (tokenGroups == null)
                throw new ArgumentNullException("tokenGroups");
            if (reference == null)
                throw new ArgumentNullException("reference");

            Dictionary<string, TokenGroupInfo> tokenBySid = tokenGroups
                .Where(group => group != null && !String.IsNullOrWhiteSpace(group.Sid))
                .GroupBy(group => group.Sid, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    group => group.Key,
                    group => group.First(),
                    StringComparer.OrdinalIgnoreCase);
            HashSet<string> referenceSids = new HashSet<string>(
                reference.DomainGroupSids,
                StringComparer.OrdinalIgnoreCase);
            List<GroupComparison> comparisons = new List<GroupComparison>();

            foreach (KeyValuePair<string, TokenGroupInfo> token in tokenBySid)
            {
                string name;
                reference.SidToName.TryGetValue(token.Key, out name);
                comparisons.Add(new GroupComparison
                {
                    Sid = token.Key,
                    Name = name,
                    Kind = referenceSids.Contains(token.Key)
                        ? GroupComparisonKind.Match
                        : GroupComparisonKind.TokenOnly,
                    TokenAttributes = token.Value.Attributes,
                    IsUserSid = String.Equals(
                        token.Key,
                        session.UserSid,
                        StringComparison.OrdinalIgnoreCase)
                });
            }

            foreach (string sid in referenceSids)
            {
                if (tokenBySid.ContainsKey(sid))
                {
                    continue;
                }

                string name;
                reference.SidToName.TryGetValue(sid, out name);
                comparisons.Add(new GroupComparison
                {
                    Sid = sid,
                    Name = name,
                    Kind = GroupComparisonKind.ReferenceOnly
                });
            }

            return comparisons;
        }

        public static IList<RuleMatch> Evaluate(
            LogonSessionSnapshot session,
            SessionTriggerContext trigger,
            IEnumerable<TokenGroupInfo> tokenGroups,
            MembershipResult reference,
            IEnumerable<GroupComparison> comparisons)
        {
            if (session == null)
                throw new ArgumentNullException("session");
            if (tokenGroups == null)
                throw new ArgumentNullException("tokenGroups");
            if (reference == null)
                throw new ArgumentNullException("reference");
            if (comparisons == null)
                throw new ArgumentNullException("comparisons");

            List<RuleMatch> matches = new List<RuleMatch>();
            List<TokenGroupInfo> tokenGroupList = tokenGroups.ToList();
            List<GroupComparison> comparisonList = comparisons.ToList();

            foreach (GroupComparison comparison in comparisonList.Where(
                item => item.Kind == GroupComparisonKind.TokenOnly))
            {
                matches.Add(Create(
                    TokenGroupNotInAuthoritativeMembership,
                    RuleSeverity.High,
                    RuleConfidence.High,
                    true,
                    "A token group SID is absent from authoritative membership.",
                    "Sid",
                    comparison.Sid));
            }

            foreach (GroupComparison comparison in comparisonList.Where(
                item => item.Kind == GroupComparisonKind.ReferenceOnly))
            {
                matches.Add(Create(
                    AuthoritativeGroupMissingFromToken,
                    RuleSeverity.Information,
                    RuleConfidence.Medium,
                    false,
                    "An authoritative group SID is absent from the existing token.",
                    "Sid",
                    comparison.Sid));
            }

            if (tokenGroupList.Any(group => String.Equals(
                group.Sid,
                session.UserSid,
                StringComparison.OrdinalIgnoreCase)))
            {
                matches.Add(Create(
                    UserSidPresentInGroupList,
                    RuleSeverity.Critical,
                    RuleConfidence.High,
                    true,
                    "The session user SID appears in the token group list.",
                    "UserSid",
                    session.UserSid));
            }

            AddIdentityRules(matches, session, reference);
            AddAttributeRules(matches, tokenGroupList);
            AddCrossDomainRules(matches, session, reference, comparisonList);
            AddEventRules(matches, session, trigger);
            return matches;
        }

        private static void AddIdentityRules(
            ICollection<RuleMatch> matches,
            LogonSessionSnapshot session,
            MembershipResult reference)
        {
            bool sidMismatch = !String.IsNullOrWhiteSpace(reference.ResolvedUserSid) &&
                !String.Equals(
                    reference.ResolvedUserSid,
                    session.UserSid,
                    StringComparison.OrdinalIgnoreCase);
            bool nameMismatch = !String.IsNullOrWhiteSpace(
                    reference.ResolvedSamAccountName) &&
                !String.IsNullOrWhiteSpace(session.AccountName) &&
                !String.Equals(
                    reference.ResolvedSamAccountName,
                    session.AccountName,
                    StringComparison.OrdinalIgnoreCase);

            if (sidMismatch || nameMismatch)
            {
                RuleMatch match = Create(
                    UserNameSidMismatch,
                    RuleSeverity.High,
                    RuleConfidence.High,
                    true,
                    "The authoritative account identity differs from the LSA identity.",
                    "LsaUserSid",
                    session.UserSid);
                match.Evidence["ResolvedUserSid"] =
                    reference.ResolvedUserSid ?? String.Empty;
                match.Evidence["LsaAccountName"] =
                    session.AccountName ?? String.Empty;
                match.Evidence["ResolvedAccountName"] =
                    reference.ResolvedSamAccountName ?? String.Empty;
                matches.Add(match);
            }

            if (reference.AccountExists == false)
            {
                matches.Add(Create(
                    AccountDoesNotExist,
                    RuleSeverity.Critical,
                    RuleConfidence.High,
                    true,
                    "The LSA user SID does not resolve to an authoritative account.",
                    "UserSid",
                    session.UserSid));
            }

            if (reference.AccountEnabled == false)
            {
                matches.Add(Create(
                    AccountDisabled,
                    RuleSeverity.High,
                    RuleConfidence.High,
                    true,
                    "The authoritative account is disabled.",
                    "UserSid",
                    session.UserSid));
            }
        }

        private static void AddAttributeRules(
            ICollection<RuleMatch> matches,
            IEnumerable<TokenGroupInfo> tokenGroups)
        {
            foreach (TokenGroupInfo group in tokenGroups)
            {
                if ((group.Attributes & SeGroupEnabled) != 0 &&
                    (group.Attributes & SeGroupUseForDenyOnly) != 0)
                {
                    RuleMatch match = Create(
                        TokenGroupAttributeMismatch,
                        RuleSeverity.High,
                        RuleConfidence.High,
                        true,
                        "A token group is both enabled and deny-only.",
                        "Sid",
                        group.Sid);
                    match.Evidence["Attributes"] =
                        "0x" + group.Attributes.ToString("X8");
                    matches.Add(match);
                }
            }
        }

        private static void AddCrossDomainRules(
            ICollection<RuleMatch> matches,
            LogonSessionSnapshot session,
            MembershipResult reference,
            IEnumerable<GroupComparison> comparisons)
        {
            SecurityIdentifier userSid;
            try
            {
                userSid = new SecurityIdentifier(session.UserSid);
            }
            catch (ArgumentException)
            {
                return;
            }

            SecurityIdentifier userDomainSid = userSid.AccountDomainSid;
            if (userDomainSid == null)
            {
                return;
            }

            foreach (GroupComparison comparison in comparisons.Where(
                item => item.Kind == GroupComparisonKind.TokenOnly))
            {
                try
                {
                    SecurityIdentifier groupSid =
                        new SecurityIdentifier(comparison.Sid);
                    SecurityIdentifier groupDomainSid = groupSid.AccountDomainSid;
                    if (groupDomainSid != null &&
                        !groupDomainSid.Equals(userDomainSid))
                    {
                        if (!reference.SidHistorySids.Contains(comparison.Sid))
                        {
                            matches.Add(Create(
                                SuspiciousSidHistory,
                                RuleSeverity.High,
                                RuleConfidence.Medium,
                                true,
                                "A cross-domain token SID is absent from authoritative sIDHistory.",
                                "Sid",
                                comparison.Sid));
                        }

                        RuleMatch match = Create(
                            CrossDomainMembershipInconsistency,
                            RuleSeverity.High,
                            RuleConfidence.Medium,
                            true,
                            "A cross-domain token SID is absent from authoritative membership.",
                            "Sid",
                            comparison.Sid);
                        match.Evidence["UserDomainSid"] = userDomainSid.Value;
                        match.Evidence["GroupDomainSid"] = groupDomainSid.Value;
                        matches.Add(match);
                    }
                }
                catch (ArgumentException)
                {
                    continue;
                }
            }
        }

        private static void AddEventRules(
            ICollection<RuleMatch> matches,
            LogonSessionSnapshot session,
            SessionTriggerContext trigger)
        {
            if (trigger == null || trigger.Source != TriggerSource.Event4624)
            {
                return;
            }

            List<string> mismatches = new List<string>();
            if (trigger.TargetLogonId.HasValue &&
                trigger.TargetLogonId.Value != session.LogonId)
                mismatches.Add("TargetLogonId");
            if (Different(trigger.TargetUserSid, session.UserSid))
                mismatches.Add("TargetUserSid");
            if (Different(trigger.TargetUserName, session.AccountName))
                mismatches.Add("TargetUserName");
            if (Different(trigger.TargetDomainName, session.LogonDomain))
                mismatches.Add("TargetDomainName");
            if (trigger.LogonType.HasValue &&
                trigger.LogonType.Value != session.LogonType)
                mismatches.Add("LogonType");
            if (!String.IsNullOrWhiteSpace(trigger.AuthenticationPackage) &&
                !String.Equals(
                    trigger.AuthenticationPackage,
                    "Negotiate",
                    StringComparison.OrdinalIgnoreCase) &&
                Different(
                    trigger.AuthenticationPackage,
                    session.AuthenticationPackage))
                mismatches.Add("AuthenticationPackage");

            if (mismatches.Count != 0)
            {
                matches.Add(Create(
                    EventVsLsaIdentityMismatch,
                    RuleSeverity.High,
                    RuleConfidence.High,
                    true,
                    "Security Event 4624 identity fields differ from LSA session data.",
                    "Fields",
                    String.Join(",", mismatches)));
            }
        }

        private static bool Different(string left, string right)
        {
            return !String.IsNullOrWhiteSpace(left) &&
                !String.Equals(left, right, StringComparison.OrdinalIgnoreCase);
        }

        private static RuleMatch Create(
            string id,
            RuleSeverity severity,
            RuleConfidence confidence,
            bool suspicious,
            string description,
            string evidenceName,
            string evidenceValue)
        {
            RuleMatch match = new RuleMatch
            {
                RuleId = id,
                Severity = severity,
                Confidence = confidence,
                IsSuspicious = suspicious,
                Description = description
            };
            match.Evidence[evidenceName] = evidenceValue ?? String.Empty;
            return match;
        }
    }
}
