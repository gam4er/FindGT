using System;
using System.Diagnostics.Eventing;

namespace FindGT.Eventing
{
    internal sealed class ManifestEventWriter : IDisposable
    {
        internal static readonly Guid ProviderId =
            new Guid("24F97934-34DF-4F64-B07D-5744F7D46EED");
        private const byte OperationalChannel = 16;
        private readonly EventProvider _provider;
        private bool _disposed;

        internal ManifestEventWriter()
        {
            _provider = new EventProvider(ProviderId);
        }

        internal bool Write(
            int eventId,
            ServiceEventLevel level,
            string payload,
            out string error)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(
                    typeof(ManifestEventWriter).FullName);
            }

            if (!_provider.IsEnabled())
            {
                error = "The FindGT manifest provider is not enabled.";
                return false;
            }

            EventDescriptor descriptor = new EventDescriptor(
                eventId,
                0,
                OperationalChannel,
                ToNativeLevel(level),
                0,
                0,
                unchecked((long)0x8000000000000000UL));
            if (_provider.WriteEvent(ref descriptor, payload ?? String.Empty))
            {
                error = null;
                return true;
            }

            error = EventProvider.GetLastWriteEventError().ToString();
            return false;
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _provider.Dispose();
        }

        private static byte ToNativeLevel(ServiceEventLevel level)
        {
            switch (level)
            {
                case ServiceEventLevel.Error:
                    return 2;
                case ServiceEventLevel.Warning:
                    return 3;
                default:
                    return 4;
            }
        }
    }
}
