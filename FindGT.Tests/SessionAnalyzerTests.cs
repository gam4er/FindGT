using System;
using System.Collections.Generic;
using System.Threading;
using FindGT.Core;
using FindGT.Core.Analysis;
using FindGT.Membership;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FindGT.Tests
{
    [TestClass]
    public sealed class SessionAnalyzerTests
    {
        [TestMethod]
        public void MatchingReferenceProducesCleanVerdict()
        {
            TestHarness harness = CreateHarness(
                TestFixtures.Reference(TestFixtures.DomainUsersSid),
                Group(TestFixtures.DomainUsersSid));

            SessionAnalysisResult result = harness.Analyzer.AnalyzeSession(
                harness.LogonId,
                SessionTriggerContext.ForCli(),
                CancellationToken.None);

            Assert.AreEqual(AnalysisVerdict.Clean, result.Verdict);
            Assert.AreEqual(ProcessingStatus.Completed, result.ProcessingStatus);
            Assert.AreEqual(0, result.TokenOnlyGroupCount);
        }

        [TestMethod]
        public void TokenOnlyGroupProducesSuspiciousVerdict()
        {
            TestHarness harness = CreateHarness(
                TestFixtures.Reference(TestFixtures.DomainUsersSid),
                Group(TestFixtures.DomainUsersSid),
                Group(TestFixtures.DomainAdminsSid));

            SessionAnalysisResult result = harness.Analyzer.AnalyzeSession(
                harness.LogonId,
                SessionTriggerContext.ForCli(),
                CancellationToken.None);

            Assert.AreEqual(AnalysisVerdict.Suspicious, result.Verdict);
            Assert.AreEqual(1, result.TokenOnlyGroupCount);
        }

        [TestMethod]
        public void ReferenceFailureNeverProducesClean()
        {
            MembershipResult failedReference = new MembershipResult
            {
                Source = "S4U2Self/LDAP",
                Success = false,
                Error = "DC unavailable"
            };
            TestHarness harness = CreateHarness(
                failedReference,
                Group(TestFixtures.DomainUsersSid));

            SessionAnalysisResult result = harness.Analyzer.AnalyzeSession(
                harness.LogonId,
                SessionTriggerContext.ForCli(),
                CancellationToken.None);

            Assert.AreEqual(AnalysisVerdict.Unknown, result.Verdict);
            Assert.AreEqual(ProcessingStatus.Failed, result.ProcessingStatus);
            Assert.AreEqual(AnalysisReason.LdapFallbackFailed, result.Reason);
        }

        [TestMethod]
        public void PowerfulOnlySkipsRegularUser()
        {
            TestHarness harness = CreateHarness(
                TestFixtures.Reference(TestFixtures.DomainUsersSid),
                Group(TestFixtures.DomainUsersSid));
            harness.Options.PowerfulOnly.Enabled = true;

            SessionAnalysisResult result = harness.Analyzer.AnalyzeSession(
                harness.LogonId,
                SessionTriggerContext.ForCli(),
                CancellationToken.None);

            Assert.AreEqual(AnalysisVerdict.NotEvaluated, result.Verdict);
            Assert.AreEqual(ProcessingStatus.Skipped, result.ProcessingStatus);
            Assert.AreEqual(AnalysisReason.NotPowerful, result.Reason);
        }

        [TestMethod]
        public void NonKerberosSessionIsNotEvaluated()
        {
            TestHarness harness = CreateHarness(TestFixtures.Reference());
            harness.Source.Sessions[harness.LogonId].AuthenticationPackage = "NTLM";

            SessionAnalysisResult result = harness.Analyzer.AnalyzeSession(
                harness.LogonId,
                SessionTriggerContext.ForCli(),
                CancellationToken.None);

            Assert.AreEqual(AnalysisVerdict.NotEvaluated, result.Verdict);
            Assert.AreEqual(
                AnalysisReason.NonKerberosAuthenticationPackage,
                result.Reason);
        }

        [TestMethod]
        public void ExpiredSessionIsUnknown()
        {
            AnalysisOptions options = new AnalysisOptions();
            FakeSessionDataSource source = new FakeSessionDataSource();
            SessionAnalyzer analyzer = new SessionAnalyzer(
                options,
                source,
                new FakeReferenceResolver
                {
                    Result = TestFixtures.Reference()
                });

            SessionAnalysisResult result = analyzer.AnalyzeSession(
                new LUID(99),
                SessionTriggerContext.ForCli(),
                CancellationToken.None);

            Assert.AreEqual(AnalysisVerdict.Unknown, result.Verdict);
            Assert.AreEqual(
                AnalysisReason.SessionExpiredBeforeAnalysis,
                result.Reason);
        }

        [TestMethod]
        public void InternalDataSourceFailureProducesError()
        {
            TestHarness harness = CreateHarness(TestFixtures.Reference());
            harness.Source.GroupFailure =
                new InvalidOperationException("synthetic failure");

            SessionAnalysisResult result = harness.Analyzer.AnalyzeSession(
                harness.LogonId,
                SessionTriggerContext.ForCli(),
                CancellationToken.None);

            Assert.AreEqual(AnalysisVerdict.Error, result.Verdict);
            Assert.AreEqual(AnalysisReason.InternalError, result.Reason);
        }

        [TestMethod]
        public void DifferentLuidsOfSameUserRemainDistinct()
        {
            AnalysisOptions options = new AnalysisOptions();
            FakeSessionDataSource source = new FakeSessionDataSource();
            LUID first = new LUID(0x12345678);
            LUID second = new LUID(0x0000000112345678);
            source.Sessions[first] = TestFixtures.Session(first.Value);
            source.Sessions[second] = TestFixtures.Session(second.Value);
            source.Groups[first] = new[] { Group(TestFixtures.DomainUsersSid) };
            source.Groups[second] = new[] { Group(TestFixtures.DomainUsersSid) };
            SessionAnalyzer analyzer = new SessionAnalyzer(
                options,
                source,
                new FakeReferenceResolver
                {
                    Result = TestFixtures.Reference(TestFixtures.DomainUsersSid)
                });

            SessionAnalysisResult firstResult = analyzer.AnalyzeSession(
                first,
                SessionTriggerContext.ForCli(),
                CancellationToken.None);
            SessionAnalysisResult secondResult = analyzer.AnalyzeSession(
                second,
                SessionTriggerContext.ForCli(),
                CancellationToken.None);

            Assert.AreNotEqual(firstResult.Session.LogonId, secondResult.Session.LogonId);
            Assert.AreNotEqual(firstResult.AnalysisId, secondResult.AnalysisId);
        }

        private static TestHarness CreateHarness(
            MembershipResult reference,
            params TokenGroupInfo[] groups)
        {
            LUID logonId = new LUID(1);
            AnalysisOptions options = new AnalysisOptions();
            FakeSessionDataSource source = new FakeSessionDataSource();
            source.Sessions[logonId] = TestFixtures.Session(logonId.Value);
            source.Groups[logonId] =
                new List<TokenGroupInfo>(groups).AsReadOnly();
            FakeReferenceResolver resolver = new FakeReferenceResolver
            {
                Result = reference
            };

            return new TestHarness
            {
                LogonId = logonId,
                Options = options,
                Source = source,
                Analyzer = new SessionAnalyzer(options, source, resolver)
            };
        }

        private static TokenGroupInfo Group(string sid)
        {
            return new TokenGroupInfo { Sid = sid, Attributes = 4 };
        }

        private sealed class TestHarness
        {
            internal LUID LogonId { get; set; }
            internal AnalysisOptions Options { get; set; }
            internal FakeSessionDataSource Source { get; set; }
            internal SessionAnalyzer Analyzer { get; set; }
        }
    }
}
