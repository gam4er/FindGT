using System;
using System.Collections.Generic;
using FindGT.Core;

namespace FindGT.Eventing
{
    public enum ServiceHealthState
    {
        Healthy,
        DegradedNoSecuritySubscription,
        DegradedNoAuditEvents,
        DegradedNoDomainController,
        DegradedS4U,
        DegradedLdap,
        DegradedSecuritySink,
        DegradedBookmark,
        DegradedQueuePressure
    }

    public enum ServiceEventLevel
    {
        Information,
        Warning,
        Error
    }

    public static class ServiceEventIds
    {
        public const int ServiceStarted = 1000;
        public const int SessionAnalysisClean = 1001;
        public const int SessionAnalysisSuspicious = 1002;
        public const int SessionAnalysisUnknown = 1003;
        public const int SessionAnalysisError = 1004;
        public const int SessionSkippedNotPowerful = 1005;
        public const int SessionSkippedByPolicy = 1006;
        public const int SecuritySubscriptionError = 1010;
        public const int SessionRecoveredByReconciliation = 1011;
        public const int QueuePressure = 1012;
        public const int SecuritySinkUnavailable = 1013;
        public const int BookmarkInvalid = 1014;
        public const int DomainControllerUnavailable = 1015;
        public const int ConfigurationInvalid = 1016;
        public const int ServiceStopped = 1020;
    }

    public sealed class ServiceEventRecord
    {
        public ServiceEventRecord()
        {
            TimestampUtc = DateTime.UtcNow;
            Properties = new Dictionary<string, string>(
                StringComparer.OrdinalIgnoreCase);
        }

        public int EventId { get; set; }
        public ServiceEventLevel Level { get; set; }
        public DateTime TimestampUtc { get; set; }
        public string Message { get; set; }
        public ServiceHealthState HealthState { get; set; }
        public IDictionary<string, string> Properties { get; private set; }
    }

    public sealed class SinkWriteResult
    {
        public bool OperationalPersisted { get; set; }
        public bool SecurityPersisted { get; set; }
        public string Error { get; set; }
    }

    public interface IServiceEventSink : IDisposable
    {
        SinkWriteResult WriteAnalysis(SessionAnalysisResult result);
        bool WriteServiceEvent(ServiceEventRecord record);
    }

    public interface IServiceEventSinkStatus
    {
        string SecurityInitializationError { get; }
    }
}
