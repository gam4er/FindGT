using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FindGT.Core;
using FindGT.Core.Analysis;
using FindGT.Eventing;
using FindGT.Service.Configuration;

namespace FindGT.Service.Runtime
{
    internal sealed class FindGtServiceRuntime : IDisposable
    {
        private readonly object _lifecycleSync = new object();
        private readonly ConfigurationLoadResult _configurationResult;
        private readonly ServiceConfiguration _configuration;
        private readonly ISessionAnalyzer _analyzer;
        private readonly IServiceEventSink _sink;
        private readonly IEventSubscriptionFactory _subscriptionFactory;
        private readonly EventBookmarkStore _bookmarkStore;
        private readonly BoundedSessionQueue _queue;
        private readonly SessionDeduplicator _dedupe;
        private readonly ServiceHealthTracker _health = new ServiceHealthTracker();
        private readonly string _machineId;
        private readonly Guid _bootInstanceId;
        private CancellationTokenSource _cancellation;
        private IEventSubscription _subscription;
        private List<Task> _workers;
        private Task _reconciliationTask;
        private Timer _reconciliationTimer;
        private int _reconciliationScheduled;
        private bool _started;
        private bool _disposed;

        internal FindGtServiceRuntime(
            ConfigurationLoadResult configurationResult,
            ISessionAnalyzer analyzer,
            IServiceEventSink sink,
            IEventSubscriptionFactory subscriptionFactory,
            EventBookmarkStore bookmarkStore)
        {
            _configurationResult = configurationResult ??
                throw new ArgumentNullException("configurationResult");
            _configuration = configurationResult.Configuration ??
                throw new ArgumentException(
                    "The configuration result does not contain a configuration.",
                    "configurationResult");
            _analyzer = analyzer ?? throw new ArgumentNullException("analyzer");
            _sink = sink ?? throw new ArgumentNullException("sink");
            _subscriptionFactory = subscriptionFactory ??
                throw new ArgumentNullException("subscriptionFactory");
            _bookmarkStore = bookmarkStore ??
                throw new ArgumentNullException("bookmarkStore");
            _queue = new BoundedSessionQueue(_configuration.Queue.Capacity);
            _dedupe = new SessionDeduplicator(TimeSpan.FromHours(24));
            _machineId = Environment.MachineName;
            _bootInstanceId = RuntimeIdentity.BootInstanceId;
        }

        internal bool IsRunning
        {
            get
            {
                lock (_lifecycleSync)
                {
                    return _started;
                }
            }
        }

        internal int QueueDepth
        {
            get { return _queue.Count; }
        }

        internal void Start()
        {
            lock (_lifecycleSync)
            {
                ThrowIfDisposed();
                if (_started)
                {
                    throw new InvalidOperationException(
                        "The FindGT service runtime is already started.");
                }

                _cancellation = new CancellationTokenSource();
                _workers = new List<Task>();
                _started = true;
            }

            if (!_configurationResult.IsValid)
            {
                WriteServiceEvent(
                    ServiceEventIds.ConfigurationInvalid,
                    ServiceEventLevel.Warning,
                    ServiceHealthState.Healthy,
                    "Configuration is invalid; safe defaults are active: " +
                    _configurationResult.Error);
            }

            IServiceEventSinkStatus sinkStatus =
                _sink as IServiceEventSinkStatus;
            if (sinkStatus != null &&
                !String.IsNullOrWhiteSpace(
                    sinkStatus.SecurityInitializationError))
            {
                SetDegraded(
                    ServiceHealthState.DegradedSecuritySink,
                    ServiceEventIds.SecuritySinkUnavailable,
                    "Security sink initialization failed: " +
                    sinkStatus.SecurityInitializationError);
            }

            EventBookmark bookmark;
            string bookmarkError;
            TimeSpan? replayWindow = null;
            if (!_bookmarkStore.TryLoad(out bookmark, out bookmarkError))
            {
                bookmark = null;
                replayWindow = TimeSpan.FromHours(24);
                SetDegraded(
                    ServiceHealthState.DegradedBookmark,
                    ServiceEventIds.BookmarkInvalid,
                    "Security bookmark is invalid; starting without it: " +
                    bookmarkError);
            }
            else if (!String.IsNullOrWhiteSpace(bookmarkError))
            {
                SetDegraded(
                    ServiceHealthState.DegradedBookmark,
                    ServiceEventIds.BookmarkInvalid,
                    bookmarkError);
            }

            StartWorkers();
            StartSubscription(bookmark, replayWindow);

            if (_configuration.AnalyzeExistingSessionsOnStart)
            {
                ScheduleReconciliation(
                    TriggerSource.StartupReconciliation);
            }

            int intervalMilliseconds = checked(
                _configuration.ReconciliationIntervalSeconds * 1000);
            _reconciliationTimer = new Timer(
                ReconciliationTimerElapsed,
                null,
                intervalMilliseconds,
                intervalMilliseconds);

            WriteServiceEvent(
                ServiceEventIds.ServiceStarted,
                ServiceEventLevel.Information,
                _health.Current,
                "FindGT service started.");
        }

        internal bool Stop(TimeSpan timeout)
        {
            CancellationTokenSource cancellation;
            List<Task> workers;
            Task reconciliation;
            IEventSubscription subscription;
            Timer timer;

            lock (_lifecycleSync)
            {
                if (!_started)
                {
                    return true;
                }

                _started = false;
                cancellation = _cancellation;
                workers = _workers;
                reconciliation = _reconciliationTask;
                subscription = _subscription;
                _subscription = null;
                timer = _reconciliationTimer;
                _reconciliationTimer = null;
            }

            StopSubscription(subscription);
            DisposeTimerAndWait(timer, timeout);
            cancellation.Cancel();
            _queue.Complete();

            List<Task> pending = new List<Task>(workers);
            if (reconciliation != null)
            {
                pending.Add(reconciliation);
            }

            bool drained = WaitForTasks(pending, timeout);
            WriteServiceEvent(
                ServiceEventIds.ServiceStopped,
                drained ? ServiceEventLevel.Information : ServiceEventLevel.Warning,
                _health.Current,
                drained
                    ? "FindGT service stopped."
                    : "FindGT service stopped before all background work drained.");
            return drained;
        }

        public void Dispose()
        {
            lock (_lifecycleSync)
            {
                if (_disposed)
                {
                    return;
                }
            }

            Stop(TimeSpan.FromSeconds(15));
            lock (_lifecycleSync)
            {
                _disposed = true;
            }

            _cancellation?.Dispose();
            _queue.Dispose();
            _subscription?.Dispose();
            _sink.Dispose();
        }

        private void StartSubscription(
            EventBookmark bookmark,
            TimeSpan? replayWindow)
        {
            IEventSubscription subscription = _subscriptionFactory.Create(
                OnCandidate,
                OnSubscriptionError);
            try
            {
                subscription.Start(bookmark, replayWindow);
                _subscription = subscription;
                _health.Clear(
                    ServiceHealthState.DegradedNoSecuritySubscription);
            }
            catch (EventLogException exception)
            {
                subscription.Dispose();
                SetSubscriptionDegraded(exception);
                if (bookmark != null)
                {
                    StartReplaySubscription(TimeSpan.FromHours(24));
                }
            }
            catch (UnauthorizedAccessException exception)
            {
                subscription.Dispose();
                SetSubscriptionDegraded(exception);
            }
        }

        private void StartReplaySubscription(TimeSpan replayWindow)
        {
            IEventSubscription replay = _subscriptionFactory.Create(
                OnCandidate,
                OnSubscriptionError);
            try
            {
                replay.Start(null, replayWindow);
                _subscription = replay;
                _health.Clear(
                    ServiceHealthState.DegradedNoSecuritySubscription);
                SetDegraded(
                    ServiceHealthState.DegradedBookmark,
                    ServiceEventIds.BookmarkInvalid,
                    "The saved bookmark was rejected; replaying the last 24 hours.");
            }
            catch (EventLogException exception)
            {
                replay.Dispose();
                SetSubscriptionDegraded(exception);
            }
            catch (UnauthorizedAccessException exception)
            {
                replay.Dispose();
                SetSubscriptionDegraded(exception);
            }
        }

        private void StopSubscription(IEventSubscription subscription)
        {
            if (subscription == null)
            {
                return;
            }

            try
            {
                subscription.Stop();
            }
            catch (EventLogException exception)
            {
                WriteServiceEvent(
                    ServiceEventIds.SecuritySubscriptionError,
                    ServiceEventLevel.Warning,
                    ServiceHealthState.DegradedNoSecuritySubscription,
                    "Security subscription stop failed: " + exception.Message);
            }
            catch (InvalidOperationException exception)
            {
                WriteServiceEvent(
                    ServiceEventIds.SecuritySubscriptionError,
                    ServiceEventLevel.Warning,
                    ServiceHealthState.DegradedNoSecuritySubscription,
                    "Security subscription stop failed: " + exception.Message);
            }
            finally
            {
                subscription.Dispose();
            }
        }

        private void StartWorkers()
        {
            for (int index = 0;
                 index < _configuration.Queue.WorkerCount;
                 index++)
            {
                Task worker = Task.Factory.StartNew(
                    ConsumeQueue,
                    CancellationToken.None,
                    TaskCreationOptions.LongRunning,
                    TaskScheduler.Default);
                _workers.Add(worker);
            }
        }

        private void ConsumeQueue()
        {
            try
            {
                foreach (SessionCandidate candidate in _queue.Consume(
                    _cancellation.Token))
                {
                    Task processing = Task.Factory.StartNew(
                        delegate
                        {
                            ProcessCandidate(candidate, _cancellation.Token);
                        },
                        CancellationToken.None,
                        TaskCreationOptions.DenyChildAttach,
                        TaskScheduler.Default);
                    WaitHandle completed =
                        ((IAsyncResult)processing).AsyncWaitHandle;
                    try
                    {
                        completed.WaitOne();
                    }
                    finally
                    {
                        completed.Dispose();
                    }

                    if (!processing.IsFaulted)
                    {
                        continue;
                    }

                    AggregateException failure =
                        processing.Exception.Flatten();
                    _dedupe.Release(Key(candidate.LogonId));
                    if (_cancellation.IsCancellationRequested &&
                        failure.InnerExceptions.All(
                            exception =>
                                exception is OperationCanceledException))
                    {
                        break;
                    }

                    WriteServiceEvent(
                        ServiceEventIds.SessionAnalysisError,
                        ServiceEventLevel.Error,
                        _health.Current,
                        "Unhandled candidate failure for LUID " +
                        candidate.LogonId + ": " +
                        FormatFailure(failure));
                    ScheduleReconciliation(
                        TriggerSource.PeriodicReconciliation);
                }
            }
            catch (OperationCanceledException)
            {
                // Expected during bounded service shutdown.
            }
        }

        private void ProcessCandidate(
            SessionCandidate candidate,
            CancellationToken cancellationToken)
        {
            SessionIdentityKey key = Key(candidate.LogonId);
            SessionAnalysisResult result = null;
            int[] delays = _configuration.RetryDelaysMilliseconds;

            for (int retry = 0; retry < delays.Length; retry++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (delays[retry] != 0 &&
                    cancellationToken.WaitHandle.WaitOne(delays[retry]))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                }

                result = _analyzer.AnalyzeSession(
                    candidate.LogonId,
                    candidate.Trigger,
                    cancellationToken);
                result.RetryCount = retry;
                if (!ShouldRetry(result) || retry == delays.Length - 1)
                {
                    break;
                }
            }

            SinkWriteResult write = _sink.WriteAnalysis(result);
            if (!write.OperationalPersisted)
            {
                _dedupe.Release(key);
                SetDegraded(
                    ServiceHealthState.DegradedSecuritySink,
                    ServiceEventIds.SecuritySinkUnavailable,
                    "Analysis result was not persisted: " + write.Error);
                ScheduleReconciliation(TriggerSource.PeriodicReconciliation);
                return;
            }

            if (!write.SecurityPersisted)
            {
                SetDegraded(
                    ServiceHealthState.DegradedSecuritySink,
                    ServiceEventIds.SecuritySinkUnavailable,
                    "Security summary was not persisted: " + write.Error);
            }
            else
            {
                _health.Clear(ServiceHealthState.DegradedSecuritySink);
            }

            if (candidate.Bookmark != null)
            {
                SaveBookmark(candidate.Bookmark);
            }

            UpdateHealthFromResult(result);
            if (IsRetryableUnknown(result))
            {
                _dedupe.Release(key);
            }
            else
            {
                _dedupe.MarkCompleted(key);
            }
        }

        private void OnCandidate(SessionCandidate candidate)
        {
            if (IsAcceptingCallbacks())
            {
                QueueCandidate(candidate);
            }
        }

        private bool QueueCandidate(SessionCandidate candidate)
        {
            SessionIdentityKey key = Key(candidate.LogonId);
            if (!_dedupe.TryBegin(key))
            {
                return false;
            }

            if (_queue.TryEnqueue(candidate))
            {
                return true;
            }

            _dedupe.Release(key);
            SetDegraded(
                ServiceHealthState.DegradedQueuePressure,
                ServiceEventIds.QueuePressure,
                "The bounded analysis queue is full.");
            ScheduleReconciliation(TriggerSource.PeriodicReconciliation);
            return false;
        }

        private void ReconciliationTimerElapsed(object state)
        {
            ScheduleReconciliation(TriggerSource.PeriodicReconciliation);
        }

        private void ScheduleReconciliation(TriggerSource source)
        {
            lock (_lifecycleSync)
            {
                CancellationTokenSource cancellation = _cancellation;
                if (!_started ||
                    cancellation == null ||
                    cancellation.IsCancellationRequested ||
                    Interlocked.CompareExchange(
                        ref _reconciliationScheduled,
                        1,
                        0) != 0)
                {
                    return;
                }

                _reconciliationTask = Task.Factory.StartNew(
                    delegate
                    {
                        try
                        {
                            RunReconciliation(source);
                        }
                        finally
                        {
                            Interlocked.Exchange(
                                ref _reconciliationScheduled,
                                0);
                        }
                    },
                    CancellationToken.None,
                    TaskCreationOptions.DenyChildAttach,
                    TaskScheduler.Default);
            }
        }

        private void RunReconciliation(TriggerSource source)
        {
            try
            {
                IReadOnlyCollection<LogonSessionSnapshot> sessions =
                    _analyzer.EnumerateSessions(_cancellation.Token);
                foreach (LogonSessionSnapshot session in sessions)
                {
                    SessionCandidate candidate = new SessionCandidate
                    {
                        LogonId = session.LogonId,
                        Trigger = new SessionTriggerContext
                        {
                            Source = source,
                            TargetLogonId = session.LogonId
                        },
                        ObservedUtc = DateTime.UtcNow
                    };
                    if (QueueCandidate(candidate) &&
                        source != TriggerSource.PeriodicReconciliation)
                    {
                        WriteServiceEvent(
                            ServiceEventIds.SessionRecoveredByReconciliation,
                            ServiceEventLevel.Information,
                            _health.Current,
                            "Session " + session.LogonId +
                            " was queued by reconciliation.");
                    }
                }
            }
            catch (NativeCallException exception)
            {
                SetDegraded(
                    ServiceHealthState.DegradedNoDomainController,
                    ServiceEventIds.DomainControllerUnavailable,
                    "Session reconciliation failed: " + exception.Message);
            }
            catch (Win32Exception exception)
            {
                SetDegraded(
                    ServiceHealthState.DegradedNoSecuritySubscription,
                    ServiceEventIds.SecuritySubscriptionError,
                    "Session reconciliation failed: " + exception.Message);
            }
            catch (InvalidOperationException exception)
            {
                SetDegraded(
                    ServiceHealthState.DegradedNoSecuritySubscription,
                    ServiceEventIds.SecuritySubscriptionError,
                    "Session reconciliation failed: " + exception.Message);
            }
            catch (OperationCanceledException)
            {
                // Expected during service shutdown.
            }
        }

        private void OnSubscriptionError(Exception exception)
        {
            if (IsAcceptingCallbacks())
            {
                SetSubscriptionDegraded(exception);
                ScheduleReconciliation(TriggerSource.PeriodicReconciliation);
            }
        }

        private void SetSubscriptionDegraded(Exception exception)
        {
            SetDegraded(
                ServiceHealthState.DegradedNoSecuritySubscription,
                ServiceEventIds.SecuritySubscriptionError,
                "Security Event 4624 subscription failed: " + exception.Message);
        }

        private void SaveBookmark(EventBookmark bookmark)
        {
            try
            {
                _bookmarkStore.Save(bookmark);
                _health.Clear(ServiceHealthState.DegradedBookmark);
            }
            catch (IOException exception)
            {
                SetBookmarkDegraded(exception);
            }
            catch (UnauthorizedAccessException exception)
            {
                SetBookmarkDegraded(exception);
            }
            catch (InvalidOperationException exception)
            {
                SetBookmarkDegraded(exception);
            }
            catch (EventParseException exception)
            {
                SetBookmarkDegraded(exception);
            }
            catch (PlatformNotSupportedException exception)
            {
                SetBookmarkDegraded(exception);
            }
        }

        private void SetBookmarkDegraded(Exception exception)
        {
            SetDegraded(
                ServiceHealthState.DegradedBookmark,
                ServiceEventIds.BookmarkInvalid,
                "Security bookmark could not be saved: " + exception.Message);
        }

        private void UpdateHealthFromResult(SessionAnalysisResult result)
        {
            if (result.ReferenceSucceeded)
            {
                _health.Clear(ServiceHealthState.DegradedNoDomainController);
                _health.Clear(ServiceHealthState.DegradedS4U);
                _health.Clear(ServiceHealthState.DegradedLdap);
            }
            else if (result.Reason == AnalysisReason.LdapFallbackFailed)
            {
                _health.Set(ServiceHealthState.DegradedNoDomainController);
            }

            if (result.ProcessingStatus == ProcessingStatus.Completed)
            {
                _health.Clear(ServiceHealthState.DegradedQueuePressure);
            }
        }

        private void SetDegraded(
            ServiceHealthState state,
            int eventId,
            string message)
        {
            if (_health.Set(state))
            {
                WriteServiceEvent(
                    eventId,
                    ServiceEventLevel.Warning,
                    state,
                    message);
            }
        }

        private void WriteServiceEvent(
            int eventId,
            ServiceEventLevel level,
            ServiceHealthState healthState,
            string message)
        {
            _sink.WriteServiceEvent(new ServiceEventRecord
            {
                EventId = eventId,
                Level = level,
                HealthState = healthState,
                Message = message
            });
        }

        private SessionIdentityKey Key(LUID logonId)
        {
            return new SessionIdentityKey(
                _machineId,
                _bootInstanceId,
                logonId);
        }

        private static bool ShouldRetry(SessionAnalysisResult result)
        {
            return result.Verdict == AnalysisVerdict.Unknown &&
                (result.Reason == AnalysisReason.SessionExpiredBeforeAnalysis ||
                 result.Reason == AnalysisReason.TokenAcquisitionFailed);
        }

        private static bool IsRetryableUnknown(SessionAnalysisResult result)
        {
            return result.Verdict == AnalysisVerdict.Unknown &&
                (result.Reason == AnalysisReason.LdapFallbackFailed ||
                 result.Reason == AnalysisReason.TokenAcquisitionFailed);
        }

        private static void DisposeTimerAndWait(Timer timer, TimeSpan timeout)
        {
            if (timer == null)
            {
                return;
            }

            using (ManualResetEvent stopped = new ManualResetEvent(false))
            {
                if (timer.Dispose(stopped))
                {
                    stopped.WaitOne(timeout);
                }
            }
        }

        private bool IsAcceptingCallbacks()
        {
            lock (_lifecycleSync)
            {
                return _started && !_disposed;
            }
        }

        private static bool WaitForTasks(
            IEnumerable<Task> tasks,
            TimeSpan timeout)
        {
            Stopwatch stopwatch = Stopwatch.StartNew();
            foreach (Task task in tasks.Where(item => item != null).Distinct())
            {
                TimeSpan remaining = timeout - stopwatch.Elapsed;
                if (remaining <= TimeSpan.Zero)
                {
                    return false;
                }

                WaitHandle completed = ((IAsyncResult)task).AsyncWaitHandle;
                try
                {
                    if (!completed.WaitOne(remaining))
                    {
                        return false;
                    }
                }
                finally
                {
                    completed.Dispose();
                }

                if (task.IsFaulted)
                {
                    task.Exception.Flatten();
                }
            }

            return true;
        }

        private static string FormatFailure(AggregateException failure)
        {
            Exception first = failure.InnerExceptions.FirstOrDefault();
            string message = first == null
                ? failure.Message
                : first.GetType().Name + ": " + first.Message;
            return message.Length <= 2048
                ? message
                : message.Substring(0, 2048);
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(
                    typeof(FindGtServiceRuntime).FullName);
            }
        }
    }
}
