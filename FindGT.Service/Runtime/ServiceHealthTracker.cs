using System.Collections.Generic;
using System.Linq;
using FindGT.Eventing;

namespace FindGT.Service.Runtime
{
    internal sealed class ServiceHealthTracker
    {
        private readonly object _sync = new object();
        private readonly HashSet<ServiceHealthState> _degraded =
            new HashSet<ServiceHealthState>();

        internal ServiceHealthState Current
        {
            get
            {
                lock (_sync)
                {
                    return _degraded.Count == 0
                        ? ServiceHealthState.Healthy
                        : _degraded.OrderBy(value => value).First();
                }
            }
        }

        internal bool Set(ServiceHealthState state)
        {
            if (state == ServiceHealthState.Healthy)
            {
                return false;
            }

            lock (_sync)
            {
                return _degraded.Add(state);
            }
        }

        internal bool Clear(ServiceHealthState state)
        {
            lock (_sync)
            {
                return _degraded.Remove(state);
            }
        }

        internal IReadOnlyCollection<ServiceHealthState> Snapshot()
        {
            lock (_sync)
            {
                return _degraded.ToList().AsReadOnly();
            }
        }
    }
}
