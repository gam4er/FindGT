using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;

namespace FindGT.Eventing
{
    public sealed class BoundedSessionQueue : IDisposable
    {
        private readonly BlockingCollection<SessionCandidate> _queue;

        public BoundedSessionQueue(int capacity)
        {
            if (capacity <= 0)
            {
                throw new ArgumentOutOfRangeException("capacity");
            }

            _queue = new BlockingCollection<SessionCandidate>(
                new ConcurrentQueue<SessionCandidate>(),
                capacity);
        }

        public int Count
        {
            get { return _queue.Count; }
        }

        public bool IsAddingCompleted
        {
            get { return _queue.IsAddingCompleted; }
        }

        public bool TryEnqueue(SessionCandidate candidate)
        {
            if (candidate == null)
            {
                throw new ArgumentNullException("candidate");
            }

            if (_queue.IsAddingCompleted)
            {
                return false;
            }

            try
            {
                return _queue.TryAdd(candidate);
            }
            catch (InvalidOperationException)
            {
                return false;
            }
        }

        public IEnumerable<SessionCandidate> Consume(
            CancellationToken cancellationToken)
        {
            return _queue.GetConsumingEnumerable(cancellationToken);
        }

        public void Complete()
        {
            if (!_queue.IsAddingCompleted)
            {
                _queue.CompleteAdding();
            }
        }

        public void Dispose()
        {
            _queue.Dispose();
        }
    }
}
