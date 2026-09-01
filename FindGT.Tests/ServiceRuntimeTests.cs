using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Threading;
using FindGT.Core;
using FindGT.Core.Analysis;
using FindGT.Eventing;
using FindGT.Service.Configuration;
using FindGT.Service.Runtime;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FindGT.Tests
{
    [TestClass]
    public sealed class ServiceRuntimeTests
    {
        [TestMethod]
        public void StartupSubscribesBeforeEnumeratingAndAnalyzesExistingSession()
        {
            List<string> order = new List<string>();
            object orderSync = new object();
            LUID logonId = new LUID(0x0000000112345678);
            FakeAnalyzer analyzer = new FakeAnalyzer(logonId, order, orderSync);
            FakeSink sink = new FakeSink();
            FakeSubscriptionFactory subscriptions =
                new FakeSubscriptionFactory(order, orderSync);
            string bookmarkPath = TemporaryBookmarkPath();

            try
            {
                ConfigurationLoadResult configuration = ValidConfiguration();
                using (FindGtServiceRuntime runtime = new FindGtServiceRuntime(
                    configuration,
                    analyzer,
                    sink,
                    subscriptions,
                    new EventBookmarkStore(bookmarkPath)))
                {
                    runtime.Start();
                    Assert.IsTrue(
                        sink.AnalysisWritten.Wait(TimeSpan.FromSeconds(5)),
                        "The startup session was not analyzed.");

                    lock (orderSync)
                    {
                        Assert.AreEqual("subscribe", order[0]);
                        Assert.AreEqual("enumerate", order[1]);
                    }

                    Assert.AreEqual(1, analyzer.AnalysisCount);
                    subscriptions.Subscription.Emit(logonId);
                    Thread.Sleep(200);
                    Assert.AreEqual(
                        1,
                        analyzer.AnalysisCount,
                        "Event/reconciliation replay must be deduplicated by full LUID.");
                    Assert.IsTrue(runtime.Stop(TimeSpan.FromSeconds(5)));
                }
            }
            finally
            {
                DeleteBookmarkDirectory(bookmarkPath);
            }
        }

        [TestMethod]
        public void InvalidConfigurationEmitsWarningButStartsWithDefaults()
        {
            LUID logonId = new LUID(1);
            FakeAnalyzer analyzer = new FakeAnalyzer(
                logonId,
                new List<string>(),
                new object());
            FakeSink sink = new FakeSink();
            FakeSubscriptionFactory subscriptions =
                new FakeSubscriptionFactory(new List<string>(), new object());
            ConfigurationLoadResult configuration = ValidConfiguration();
            configuration.IsValid = false;
            configuration.UsedDefaults = true;
            configuration.Error = "synthetic invalid config";
            string bookmarkPath = TemporaryBookmarkPath();

            try
            {
                using (FindGtServiceRuntime runtime = new FindGtServiceRuntime(
                    configuration,
                    analyzer,
                    sink,
                    subscriptions,
                    new EventBookmarkStore(bookmarkPath)))
                {
                    runtime.Start();
                    lock (sink.Events)
                    {
                        Assert.IsTrue(sink.Events.Any(record =>
                            record.EventId == ServiceEventIds.ConfigurationInvalid));
                    }
                    runtime.Stop(TimeSpan.FromSeconds(5));
                }
            }
            finally
            {
                DeleteBookmarkDirectory(bookmarkPath);
            }
        }

        [TestMethod]
        public void WorkerContinuesAfterUnexpectedCandidateFailure()
        {
            LUID logonId = new LUID(7);
            FakeAnalyzer analyzer = new FakeAnalyzer(
                logonId,
                new List<string>(),
                new object())
            {
                FailFirstAnalysis = true
            };
            FakeSink sink = new FakeSink();
            FakeSubscriptionFactory subscriptions =
                new FakeSubscriptionFactory(new List<string>(), new object());
            string bookmarkPath = TemporaryBookmarkPath();

            try
            {
                using (FindGtServiceRuntime runtime = new FindGtServiceRuntime(
                    ValidConfiguration(),
                    analyzer,
                    sink,
                    subscriptions,
                    new EventBookmarkStore(bookmarkPath)))
                {
                    runtime.Start();
                    Assert.IsTrue(
                        sink.AnalysisWritten.Wait(TimeSpan.FromSeconds(5)),
                        "The supervisor did not process a candidate after the synthetic fault.");
                    Assert.IsTrue(analyzer.AnalysisCount >= 2);
                    lock (sink.Events)
                    {
                        Assert.IsTrue(sink.Events.Any(record =>
                            record.EventId == ServiceEventIds.SessionAnalysisError));
                    }
                    Assert.IsTrue(runtime.Stop(TimeSpan.FromSeconds(5)));
                }
            }
            finally
            {
                DeleteBookmarkDirectory(bookmarkPath);
            }
        }

        private static ConfigurationLoadResult ValidConfiguration()
        {
            ServiceConfiguration configuration =
                ServiceConfiguration.CreateDefault();
            configuration.ReconciliationIntervalSeconds = 60;
            return new ConfigurationLoadResult
            {
                Configuration = configuration,
                IsValid = true,
                Path = "test"
            };
        }

        private static string TemporaryBookmarkPath()
        {
            return System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "FindGT.Tests",
                Guid.NewGuid().ToString("N"),
                "Security.bookmark.xml");
        }

        private static void DeleteBookmarkDirectory(string bookmarkPath)
        {
            string directory = System.IO.Path.GetDirectoryName(bookmarkPath);
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, true);
            }
        }

        private sealed class FakeAnalyzer : ISessionAnalyzer
        {
            private readonly LUID _logonId;
            private readonly List<string> _order;
            private readonly object _orderSync;
            private int _analysisCount;
            internal bool FailFirstAnalysis { get; set; }

            internal FakeAnalyzer(
                LUID logonId,
                List<string> order,
                object orderSync)
            {
                _logonId = logonId;
                _order = order;
                _orderSync = orderSync;
            }

            internal int AnalysisCount
            {
                get { return Volatile.Read(ref _analysisCount); }
            }

            public IReadOnlyCollection<LogonSessionSnapshot> EnumerateSessions(
                CancellationToken cancellationToken)
            {
                lock (_orderSync)
                {
                    _order.Add("enumerate");
                }

                return new[]
                {
                    new LogonSessionSnapshot
                    {
                        LogonId = _logonId,
                        UserSid = TestFixtures.UserSid,
                        AccountName = "testuser",
                        UserName = "CONTOSO\\testuser",
                        LogonDomain = "CONTOSO",
                        DnsDomainName = "CONTOSO.COM",
                        AuthenticationPackage = "Kerberos",
                        LogonType = 3
                    }
                };
            }

            public SessionAnalysisResult AnalyzeSession(
                LUID logonId,
                SessionTriggerContext trigger,
                CancellationToken cancellationToken)
            {
                int count = Interlocked.Increment(ref _analysisCount);
                if (FailFirstAnalysis && count == 1)
                {
                    throw new ApplicationException("synthetic unexpected failure");
                }

                return new SessionAnalysisResult
                {
                    Session = new LogonSessionSnapshot
                    {
                        LogonId = logonId,
                        UserSid = TestFixtures.UserSid,
                        AuthenticationPackage = "Kerberos",
                        LogonType = 3
                    },
                    Trigger = trigger,
                    Verdict = AnalysisVerdict.Clean,
                    ProcessingStatus = ProcessingStatus.Completed,
                    ReferenceSucceeded = true
                };
            }
        }

        private sealed class FakeSink : IServiceEventSink
        {
            internal ManualResetEventSlim AnalysisWritten { get; } =
                new ManualResetEventSlim(false);
            internal IList<ServiceEventRecord> Events { get; } =
                new List<ServiceEventRecord>();

            public SinkWriteResult WriteAnalysis(SessionAnalysisResult result)
            {
                AnalysisWritten.Set();
                return new SinkWriteResult { OperationalPersisted = true };
            }

            public bool WriteServiceEvent(ServiceEventRecord record)
            {
                lock (Events)
                {
                    Events.Add(record);
                }

                return true;
            }

            public void Dispose()
            {
                AnalysisWritten.Dispose();
            }
        }

        private sealed class FakeSubscriptionFactory : IEventSubscriptionFactory
        {
            private readonly List<string> _order;
            private readonly object _orderSync;

            internal FakeSubscriptionFactory(
                List<string> order,
                object orderSync)
            {
                _order = order;
                _orderSync = orderSync;
            }

            internal FakeSubscription Subscription { get; private set; }

            public IEventSubscription Create(
                Action<SessionCandidate> candidateSink,
                Action<Exception> errorSink)
            {
                Subscription = new FakeSubscription(
                    candidateSink,
                    _order,
                    _orderSync);
                return Subscription;
            }
        }

        private sealed class FakeSubscription : IEventSubscription
        {
            private readonly Action<SessionCandidate> _candidateSink;
            private readonly List<string> _order;
            private readonly object _orderSync;

            internal FakeSubscription(
                Action<SessionCandidate> candidateSink,
                List<string> order,
                object orderSync)
            {
                _candidateSink = candidateSink;
                _order = order;
                _orderSync = orderSync;
            }

            public void Start(EventBookmark bookmark, TimeSpan? replayWindow)
            {
                lock (_orderSync)
                {
                    _order.Add("subscribe");
                }
            }

            internal void Emit(LUID logonId)
            {
                _candidateSink(new SessionCandidate
                {
                    LogonId = logonId,
                    Trigger = new SessionTriggerContext
                    {
                        Source = TriggerSource.Event4624,
                        TargetLogonId = logonId,
                        LogonType = 3
                    }
                });
            }

            public void Stop()
            {
            }

            public void Dispose()
            {
            }
        }
    }
}
