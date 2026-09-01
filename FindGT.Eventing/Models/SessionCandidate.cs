using System;
using System.Diagnostics.Eventing.Reader;
using FindGT.Core;

namespace FindGT.Eventing
{
    public sealed class SessionCandidate
    {
        public LUID LogonId { get; set; }
        public SessionTriggerContext Trigger { get; set; }
        public EventBookmark Bookmark { get; set; }
        public int RetryCount { get; set; }
        public DateTime ObservedUtc { get; set; }
    }

    public struct SessionIdentityKey : IEquatable<SessionIdentityKey>
    {
        public SessionIdentityKey(string machineId, Guid bootInstanceId, LUID logonId)
        {
            MachineId = machineId ?? String.Empty;
            BootInstanceId = bootInstanceId;
            LogonId = logonId;
        }

        public string MachineId { get; private set; }
        public Guid BootInstanceId { get; private set; }
        public LUID LogonId { get; private set; }

        public bool Equals(SessionIdentityKey other)
        {
            return String.Equals(
                    MachineId,
                    other.MachineId,
                    StringComparison.OrdinalIgnoreCase) &&
                BootInstanceId == other.BootInstanceId &&
                LogonId == other.LogonId;
        }

        public override bool Equals(object value)
        {
            return value is SessionIdentityKey &&
                Equals((SessionIdentityKey)value);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hash = StringComparer.OrdinalIgnoreCase.GetHashCode(
                    MachineId ?? String.Empty);
                hash = (hash * 397) ^ BootInstanceId.GetHashCode();
                hash = (hash * 397) ^ LogonId.GetHashCode();
                return hash;
            }
        }

        public static bool operator ==(
            SessionIdentityKey left,
            SessionIdentityKey right)
        {
            return left.Equals(right);
        }

        public static bool operator !=(
            SessionIdentityKey left,
            SessionIdentityKey right)
        {
            return !left.Equals(right);
        }
    }
}
