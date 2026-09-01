using System;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;

namespace FindGT.Eventing
{
    public sealed class SecurityEventLogSource : IDisposable
    {
        private const string Security4624Query =
            "*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=4624]]";

        private readonly object _sync = new object();
        private readonly Action<SessionCandidate> _candidateSink;
        private readonly Action<Exception> _errorSink;
        private EventLogWatcher _watcher;
        private bool _disposed;

        public SecurityEventLogSource(
            Action<SessionCandidate> candidateSink,
            Action<Exception> errorSink)
        {
            _candidateSink = candidateSink ??
                throw new ArgumentNullException("candidateSink");
            _errorSink = errorSink ??
                throw new ArgumentNullException("errorSink");
        }

        public bool IsRunning
        {
            get
            {
                lock (_sync)
                {
                    return _watcher != null && _watcher.Enabled;
                }
            }
        }

        public void Start(EventBookmark bookmark, TimeSpan? replayWindow)
        {
            lock (_sync)
            {
                ThrowIfDisposed();
                if (_watcher != null)
                {
                    throw new InvalidOperationException(
                        "The Security event watcher is already running.");
                }

                if (bookmark != null && replayWindow.HasValue)
                {
                    throw new ArgumentException(
                        "A bookmark and replay window cannot be used together.");
                }

                string queryText = BuildQuery(replayWindow);
                bool readExistingEvents = false;
                if (replayWindow.HasValue)
                {
                    readExistingEvents = true;
                }

                EventLogQuery query = new EventLogQuery(
                    "Security",
                    PathType.LogName,
                    queryText)
                {
                    ReverseDirection = false,
                    TolerateQueryErrors = false
                };
                EventLogWatcher watcher = new EventLogWatcher(
                    query,
                    bookmark,
                    readExistingEvents);
                watcher.EventRecordWritten += OnEventRecordWritten;
                bool started = false;
                try
                {
                    watcher.Enabled = true;
                    started = true;
                    _watcher = watcher;
                }
                finally
                {
                    if (!started)
                    {
                        watcher.EventRecordWritten -= OnEventRecordWritten;
                        watcher.Dispose();
                    }
                }
            }
        }

        public void Stop()
        {
            EventLogWatcher watcher;
            lock (_sync)
            {
                watcher = _watcher;
                _watcher = null;
            }

            if (watcher == null)
            {
                return;
            }

            try
            {
                watcher.EventRecordWritten -= OnEventRecordWritten;
                watcher.Enabled = false;
            }
            finally
            {
                watcher.Dispose();
            }
        }

        public void Dispose()
        {
            lock (_sync)
            {
                if (_disposed)
                {
                    return;
                }

                _disposed = true;
            }

            Stop();
        }

        private void OnEventRecordWritten(
            object sender,
            EventRecordWrittenEventArgs arguments)
        {
            if (arguments.EventException != null)
            {
                _errorSink(arguments.EventException);
                return;
            }

            EventRecord record = arguments.EventRecord;
            if (record == null)
            {
                _errorSink(new EventLogException(
                    "The Security subscription returned no event record."));
                return;
            }

            using (record)
            {
                try
                {
                    SessionCandidate candidate =
                        Event4624Parser.Parse(record.ToXml());
                    candidate.Bookmark = record.Bookmark;
                    _candidateSink(candidate);
                }
                catch (EventParseException exception)
                {
                    _errorSink(exception);
                }
                catch (EventLogException exception)
                {
                    _errorSink(exception);
                }
                catch (InvalidOperationException exception)
                {
                    _errorSink(exception);
                }
            }
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(
                    typeof(SecurityEventLogSource).FullName);
            }
        }

        internal static string BuildQuery(TimeSpan? replayWindow)
        {
            if (!replayWindow.HasValue)
            {
                return Security4624Query;
            }

            if (replayWindow.Value <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException("replayWindow");
            }

            long milliseconds = checked(
                (long)replayWindow.Value.TotalMilliseconds);
            return
                "*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] " +
                "and EventID=4624 and TimeCreated[timediff(@SystemTime) <= " +
                milliseconds.ToString(CultureInfo.InvariantCulture) + "]]]";
        }
    }
}
