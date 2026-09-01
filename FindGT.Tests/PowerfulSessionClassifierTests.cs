using System.Collections.Generic;
using FindGT.Core;
using FindGT.Core.Analysis;
using FindGT.Core.Rules;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FindGT.Tests
{
    [TestClass]
    public sealed class PowerfulSessionClassifierTests
    {
        [TestMethod]
        public void UserRid500IsPowerfulBut1500IsNot()
        {
            PowerfulOnlyOptions options = new PowerfulOnlyOptions();

            PowerfulSessionClassification administrator =
                PowerfulSessionClassifier.Classify(
                    TestFixtures.DomainSid + "-500",
                    EmptyGroups(),
                    options);
            PowerfulSessionClassification regular =
                PowerfulSessionClassifier.Classify(
                    TestFixtures.DomainSid + "-1500",
                    EmptyGroups(),
                    options);

            Assert.AreEqual(true, administrator.IsPowerful);
            Assert.AreEqual(false, regular.IsPowerful);
        }

        [DataTestMethod]
        [DataRow(512U)]
        [DataRow(518U)]
        [DataRow(519U)]
        public void PrivilegedGroupRidIsPowerful(uint rid)
        {
            PowerfulSessionClassification result =
                PowerfulSessionClassifier.Classify(
                    TestFixtures.UserSid,
                    Groups(TestFixtures.DomainSid + "-" + rid),
                    new PowerfulOnlyOptions());

            Assert.AreEqual(true, result.IsPowerful);
            StringAssert.StartsWith(result.MatchReason, "GroupRid:");
        }

        [TestMethod]
        public void DenyOnlyBuiltinAdministratorsStillTriggers()
        {
            PowerfulSessionClassification result =
                PowerfulSessionClassifier.Classify(
                    TestFixtures.UserSid,
                    new[]
                    {
                        new TokenGroupInfo
                        {
                            Sid = "S-1-5-32-544",
                            Attributes = 0x10
                        }
                    },
                    new PowerfulOnlyOptions());

            Assert.AreEqual(true, result.IsPowerful);
        }

        [TestMethod]
        public void CustomExactSidTriggers()
        {
            PowerfulOnlyOptions options = new PowerfulOnlyOptions();
            options.AdditionalSids.Add(TestFixtures.DomainSid + "-2100");

            PowerfulSessionClassification result =
                PowerfulSessionClassifier.Classify(
                    TestFixtures.UserSid,
                    Groups(TestFixtures.DomainSid + "-2100"),
                    options);

            Assert.AreEqual(true, result.IsPowerful);
            StringAssert.StartsWith(result.MatchReason, "AdditionalSid:");
        }

        [TestMethod]
        public void CustomUserSidTriggers()
        {
            PowerfulOnlyOptions options = new PowerfulOnlyOptions();
            options.AdditionalSids.Add(TestFixtures.UserSid);

            PowerfulSessionClassification result =
                PowerfulSessionClassifier.Classify(
                    TestFixtures.UserSid,
                    EmptyGroups(),
                    options);

            Assert.AreEqual(true, result.IsPowerful);
            StringAssert.StartsWith(result.MatchReason, "AdditionalUserSid:");
        }

        [TestMethod]
        public void MalformedUserSidIsUnknown()
        {
            PowerfulSessionClassification result =
                PowerfulSessionClassifier.Classify(
                    "not-a-sid",
                    EmptyGroups(),
                    new PowerfulOnlyOptions());

            Assert.IsNull(result.IsPowerful);
        }

        private static IEnumerable<TokenGroupInfo> EmptyGroups()
        {
            return new TokenGroupInfo[0];
        }

        private static IEnumerable<TokenGroupInfo> Groups(string sid)
        {
            return new[] { new TokenGroupInfo { Sid = sid, Attributes = 4 } };
        }
    }
}
