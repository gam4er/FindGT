using System;
using System.Diagnostics.Eventing.Reader;
using FindGT.Eventing;

namespace FindGT.Service.Runtime
{
    internal interface IEventSubscription : IDisposable
    {
        void Start(EventBookmark bookmark, TimeSpan? replayWindow);
        void Stop();
    }

    internal interface IEventSubscriptionFactory
    {
        IEventSubscription Create(
            Action<SessionCandidate> candidateSink,
            Action<Exception> errorSink);
    }

    internal sealed class EventSubscriptionFactory : IEventSubscriptionFactory
    {
        public IEventSubscription Create(
            Action<SessionCandidate> candidateSink,
            Action<Exception> errorSink)
        {
            return new EventSubscription(
                new SecurityEventLogSource(candidateSink, errorSink));
        }
    }

    internal sealed class EventSubscription : IEventSubscription
    {
        private readonly SecurityEventLogSource _source;

        internal EventSubscription(SecurityEventLogSource source)
        {
            _source = source ?? throw new ArgumentNullException("source");
        }

        public void Start(EventBookmark bookmark, TimeSpan? replayWindow)
        {
            _source.Start(bookmark, replayWindow);
        }

        public void Stop()
        {
            _source.Stop();
        }

        public void Dispose()
        {
            _source.Dispose();
        }
    }
}
