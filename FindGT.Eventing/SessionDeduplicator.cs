using System;
using System.Collections.Concurrent;

namespace FindGT.Eventing
{
    public sealed class SessionDeduplicator
    {
        private readonly object _sync = new object();
        private readonly ConcurrentDictionary<SessionIdentityKey, byte> _inFlight =
            new ConcurrentDictionary<SessionIdentityKey, byte>();
        private readonly ConcurrentDictionary<SessionIdentityKey, DateTime> _completed =
            new ConcurrentDictionary<SessionIdentityKey, DateTime>();
        private readonly TimeSpan _completedTtl;
        private readonly Func<DateTime> _utcNow;

        public SessionDeduplicator(TimeSpan completedTtl)
            : this(completedTtl, delegate { return DateTime.UtcNow; })
        {
        }

        internal SessionDeduplicator(
            TimeSpan completedTtl,
            Func<DateTime> utcNow)
        {
            if (completedTtl < TimeSpan.FromHours(24))
            {
                throw new ArgumentOutOfRangeException(
                    "completedTtl",
                    "Completed-session retention must be at least 24 hours.");
            }

            _completedTtl = completedTtl;
            _utcNow = utcNow ?? throw new ArgumentNullException("utcNow");
        }

        public int InFlightCount
        {
            get
            {
                lock (_sync)
                {
                    return _inFlight.Count;
                }
            }
        }

        public int CompletedCount
        {
            get
            {
                lock (_sync)
                {
                    return _completed.Count;
                }
            }
        }

        public bool TryBegin(SessionIdentityKey key)
        {
            lock (_sync)
            {
                RemoveExpired();
                if (_completed.ContainsKey(key))
                {
                    return false;
                }

                return _inFlight.TryAdd(key, 0);
            }
        }

        public void MarkCompleted(SessionIdentityKey key)
        {
            lock (_sync)
            {
                byte ignored;
                _inFlight.TryRemove(key, out ignored);
                _completed[key] = _utcNow();
            }
        }

        public void Release(SessionIdentityKey key)
        {
            lock (_sync)
            {
                byte ignored;
                _inFlight.TryRemove(key, out ignored);
            }
        }

        private void RemoveExpired()
        {
            DateTime threshold = _utcNow().Subtract(_completedTtl);
            foreach (var pair in _completed)
            {
                if (pair.Value < threshold)
                {
                    DateTime ignored;
                    _completed.TryRemove(pair.Key, out ignored);
                }
            }
        }
    }
}
