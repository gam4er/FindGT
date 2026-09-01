using System.Collections.Generic;
using System.Linq;
using FindGT.Core;
using FindGT.Core.Rules;
using FindGT.Membership;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FindGT.Tests
{
    [TestClass]
    public sealed class RuleEngineTests
    {
        [TestMethod]
        public void TokenOnlyGroupProducesPrimarySuspiciousRule()
        {
            LogonSessionSnapshot session = TestFixtures.Session(1);
            MembershipResult reference = TestFixtures.Reference(
                TestFixtures.DomainUsersSid);
            TokenGroupInfo[] groups =
            {
                Group(TestFixtures.DomainUsersSid, 4),
                Group(TestFixtures.DomainAdminsSid, 4)
            };
            IList<GroupComparison> comparisons =
                RuleEngine.BuildComparisons(session, groups, reference);

            IList<RuleMatch> matches = RuleEngine.Evaluate(
                session,
                SessionTriggerContext.ForCli(),
                groups,
                reference,
                comparisons);

            Assert.IsTrue(matches.Any(match =>
                match.RuleId == RuleEngine.TokenGroupNotInAuthoritativeMembership &&
                match.IsSuspicious));
        }

        [TestMethod]
        public void ReferenceOnlyGroupIsInformational()
        {
            LogonSessionSnapshot session = TestFixtures.Session(1);
            MembershipResult reference = TestFixtures.Reference(
                TestFixtures.DomainUsersSid,
                TestFixtures.DomainAdminsSid);
            TokenGroupInfo[] groups = { Group(TestFixtures.DomainUsersSid, 4) };
            IList<GroupComparison> comparisons =
                RuleEngine.BuildComparisons(session, groups, reference);

            IList<RuleMatch> matches = RuleEngine.Evaluate(
                session,
                SessionTriggerContext.ForCli(),
                groups,
                reference,
                comparisons);

            RuleMatch match = matches.Single(item =>
                item.RuleId == RuleEngine.AuthoritativeGroupMissingFromToken);
            Assert.IsFalse(match.IsSuspicious);
            Assert.AreEqual(RuleSeverity.Information, match.Severity);
        }

        [TestMethod]
        public void UserSidInGroupsProducesCriticalRule()
        {
            LogonSessionSnapshot session = TestFixtures.Session(1);
            MembershipResult reference = TestFixtures.Reference();
            TokenGroupInfo[] groups = { Group(TestFixtures.UserSid, 4) };
            IList<GroupComparison> comparisons =
                RuleEngine.BuildComparisons(session, groups, reference);

            IList<RuleMatch> matches = RuleEngine.Evaluate(
                session,
                SessionTriggerContext.ForCli(),
                groups,
                reference,
                comparisons);

            RuleMatch match = matches.Single(item =>
                item.RuleId == RuleEngine.UserSidPresentInGroupList);
            Assert.AreEqual(RuleSeverity.Critical, match.Severity);
            Assert.IsTrue(match.IsSuspicious);
        }

        [TestMethod]
        public void MissingAndDisabledAccountsProduceRules()
        {
            LogonSessionSnapshot session = TestFixtures.Session(1);
            MembershipResult reference = TestFixtures.Reference();
            reference.AccountExists = false;
            reference.AccountEnabled = false;

            IList<RuleMatch> matches = RuleEngine.Evaluate(
                session,
                SessionTriggerContext.ForCli(),
                new TokenGroupInfo[0],
                reference,
                new GroupComparison[0]);

            Assert.IsTrue(matches.Any(match =>
                match.RuleId == RuleEngine.AccountDoesNotExist));
            Assert.IsTrue(matches.Any(match =>
                match.RuleId == RuleEngine.AccountDisabled));
        }

        [TestMethod]
        public void AuthoritativeUserSidMismatchProducesRule()
        {
            LogonSessionSnapshot session = TestFixtures.Session(1);
            MembershipResult reference = TestFixtures.Reference();
            reference.ResolvedUserSid = TestFixtures.DomainSid + "-1200";

            IList<RuleMatch> matches = RuleEngine.Evaluate(
                session,
                SessionTriggerContext.ForCli(),
                new TokenGroupInfo[0],
                reference,
                new GroupComparison[0]);

            Assert.IsTrue(matches.Any(match =>
                match.RuleId == RuleEngine.UserNameSidMismatch &&
                match.IsSuspicious));
        }

        [TestMethod]
        public void ContradictoryGroupAttributesProduceRule()
        {
            LogonSessionSnapshot session = TestFixtures.Session(1);
            MembershipResult reference = TestFixtures.Reference(
                TestFixtures.DomainUsersSid);
            TokenGroupInfo[] groups =
            {
                Group(TestFixtures.DomainUsersSid, 0x00000014)
            };
            IList<GroupComparison> comparisons =
                RuleEngine.BuildComparisons(session, groups, reference);

            IList<RuleMatch> matches = RuleEngine.Evaluate(
                session,
                SessionTriggerContext.ForCli(),
                groups,
                reference,
                comparisons);

            Assert.IsTrue(matches.Any(match =>
                match.RuleId == RuleEngine.TokenGroupAttributeMismatch));
        }

        [TestMethod]
        public void CrossDomainTokenOnlySidProducesRule()
        {
            LogonSessionSnapshot session = TestFixtures.Session(1);
            MembershipResult reference = TestFixtures.Reference();
            TokenGroupInfo[] groups =
            {
                Group(TestFixtures.OtherDomainSid + "-512", 4)
            };
            IList<GroupComparison> comparisons =
                RuleEngine.BuildComparisons(session, groups, reference);

            IList<RuleMatch> matches = RuleEngine.Evaluate(
                session,
                SessionTriggerContext.ForCli(),
                groups,
                reference,
                comparisons);

            Assert.IsTrue(matches.Any(match =>
                match.RuleId == RuleEngine.CrossDomainMembershipInconsistency));
            Assert.IsTrue(matches.Any(match =>
                match.RuleId == RuleEngine.SuspiciousSidHistory));
        }

        [TestMethod]
        public void EventIdentityMismatchProducesRule()
        {
            LogonSessionSnapshot session = TestFixtures.Session(1);
            SessionTriggerContext trigger = new SessionTriggerContext
            {
                Source = TriggerSource.Event4624,
                TargetLogonId = session.LogonId,
                TargetUserSid = session.UserSid,
                TargetUserName = "another-user",
                TargetDomainName = session.LogonDomain,
                LogonType = session.LogonType,
                AuthenticationPackage = "Negotiate"
            };
            MembershipResult reference = TestFixtures.Reference();

            IList<RuleMatch> matches = RuleEngine.Evaluate(
                session,
                trigger,
                new TokenGroupInfo[0],
                reference,
                new GroupComparison[0]);

            RuleMatch match = matches.Single(item =>
                item.RuleId == RuleEngine.EventVsLsaIdentityMismatch);
            StringAssert.Contains(match.Evidence["Fields"], "TargetUserName");
        }

        [TestMethod]
        public void NegotiateEventPackageMatchesKerberosLsaPackage()
        {
            LogonSessionSnapshot session = TestFixtures.Session(1);
            SessionTriggerContext trigger = new SessionTriggerContext
            {
                Source = TriggerSource.Event4624,
                TargetLogonId = session.LogonId,
                TargetUserSid = session.UserSid,
                TargetUserName = session.AccountName,
                TargetDomainName = session.LogonDomain,
                LogonType = session.LogonType,
                AuthenticationPackage = "Negotiate"
            };

            IList<RuleMatch> matches = RuleEngine.Evaluate(
                session,
                trigger,
                new TokenGroupInfo[0],
                TestFixtures.Reference(),
                new GroupComparison[0]);

            Assert.IsFalse(matches.Any(match =>
                match.RuleId == RuleEngine.EventVsLsaIdentityMismatch));
        }

        private static TokenGroupInfo Group(string sid, uint attributes)
        {
            return new TokenGroupInfo { Sid = sid, Attributes = attributes };
        }
    }
}
