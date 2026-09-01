using System;
using System.Collections.Generic;
using FindGT;

namespace FindGT.Core
{
    public enum ProcessingStatus
    {
        Completed,
        Skipped,
        Failed
    }

    public enum AnalysisVerdict
    {
        Clean,
        Suspicious,
        Unknown,
        NotEvaluated,
        Error
    }

    public enum TriggerSource
    {
        Cli,
        Event4624,
        StartupReconciliation,
        PeriodicReconciliation,
        Retry
    }

    public enum AnalysisReason
    {
        None,
        SessionExpiredBeforeAnalysis,
        UnsupportedLogonType,
        NonKerberosAuthenticationPackage,
        ExcludedByPolicy,
        NotPowerful,
        PowerfulClassificationFailed,
        TokenAcquisitionFailed,
        DomainControllerUnavailable,
        S4U2SelfFailed,
        LdapFallbackFailed,
        AccountNotResolvable,
        InternalError
    }

    public enum RuleSeverity
    {
        Information,
        Low,
        Medium,
        High,
        Critical
    }

    public enum RuleConfidence
    {
        Low,
        Medium,
        High
    }

    public enum GroupComparisonKind
    {
        Match,
        TokenOnly,
        ReferenceOnly
    }

    public sealed class SessionTriggerContext
    {
        public TriggerSource Source { get; set; }
        public long? EventRecordId { get; set; }
        public DateTime? EventTimeUtc { get; set; }
        public LUID? TargetLogonId { get; set; }
        public string TargetUserSid { get; set; }
        public string TargetUserName { get; set; }
        public string TargetDomainName { get; set; }
        public uint? LogonType { get; set; }
        public string AuthenticationPackage { get; set; }
        public string LogonProcessName { get; set; }
        public string WorkstationName { get; set; }
        public string IpAddress { get; set; }
        public string IpPort { get; set; }
        public string ProcessId { get; set; }
        public string ProcessName { get; set; }
        public Guid? LogonGuid { get; set; }
        public LUID? LinkedLogonId { get; set; }

        public static SessionTriggerContext ForCli()
        {
            return new SessionTriggerContext { Source = TriggerSource.Cli };
        }
    }

    public sealed class LogonSessionSnapshot
    {
        public LUID LogonId { get; set; }
        public string UserName { get; set; }
        public string AccountName { get; set; }
        public string CredentialUserName { get; set; }
        public string LogonDomain { get; set; }
        public string DnsDomainName { get; set; }
        public string Upn { get; set; }
        public string UserSid { get; set; }
        public uint LogonType { get; set; }
        public string AuthenticationPackage { get; set; }
        public uint SessionId { get; set; }
        public DateTime? LogonTimeUtc { get; set; }
        public string LogonServer { get; set; }
        public uint UserFlags { get; set; }
    }

    public sealed class TokenGroupInfo
    {
        public string Sid { get; set; }
        public uint Attributes { get; set; }
    }

    public sealed class GroupComparison
    {
        public string Sid { get; set; }
        public string Name { get; set; }
        public GroupComparisonKind Kind { get; set; }
        public uint? TokenAttributes { get; set; }
        public bool IsUserSid { get; set; }
    }

    public sealed class RuleMatch
    {
        public string RuleId { get; set; }
        public RuleSeverity Severity { get; set; }
        public RuleConfidence Confidence { get; set; }
        public bool IsSuspicious { get; set; }
        public string Description { get; set; }
        public IDictionary<string, string> Evidence { get; set; } =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    }

    public sealed class PowerfulSessionClassification
    {
        public bool? IsPowerful { get; set; }
        public string MatchReason { get; set; }
    }

    public sealed class SessionAnalysisResult
    {
        public SessionAnalysisResult()
        {
            AnalysisId = Guid.NewGuid();
            TimestampUtc = DateTime.UtcNow;
            RuleMatches = new List<RuleMatch>();
            GroupComparisons = new List<GroupComparison>();
            TokenGroups = new List<TokenGroupInfo>();
        }

        public int SchemaVersion { get; set; } = 1;
        public string ProductVersion { get; set; }
        public Guid AnalysisId { get; set; }
        public DateTime TimestampUtc { get; set; }
        public string ComputerName { get; set; }
        public Guid BootInstanceId { get; set; }
        public SessionTriggerContext Trigger { get; set; }
        public LogonSessionSnapshot Session { get; set; }
        public string ReferenceProvider { get; set; }
        public bool ReferenceSucceeded { get; set; }
        public string ReferenceError { get; set; }
        public bool? AccountExists { get; set; }
        public bool? AccountEnabled { get; set; }
        public IList<TokenGroupInfo> TokenGroups { get; private set; }
        public int TokenGroupCount { get; set; }
        public int ReferenceGroupCount { get; set; }
        public int TokenOnlyGroupCount { get; set; }
        public int ReferenceOnlyGroupCount { get; set; }
        public bool PowerfulOnlyEnabled { get; set; }
        public bool? PowerfulSession { get; set; }
        public string PowerfulMatchReason { get; set; }
        public AnalysisVerdict Verdict { get; set; }
        public ProcessingStatus ProcessingStatus { get; set; }
        public AnalysisReason Reason { get; set; }
        public IList<RuleMatch> RuleMatches { get; private set; }
        public IList<GroupComparison> GroupComparisons { get; private set; }
        public long DurationMilliseconds { get; set; }
        public int RetryCount { get; set; }
        public string ErrorCode { get; set; }
        public string ErrorMessage { get; set; }
        public bool PayloadTruncated { get; set; }
    }
}
