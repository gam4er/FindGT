using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using FindGT.Core.Rules;
using FindGT.Membership;

namespace FindGT.Core.Analysis
{
    public sealed class SessionAnalyzer : ISessionAnalyzer
    {
        private readonly AnalysisOptions _options;
        private readonly ISessionDataSource _sessions;
        private readonly IReferenceMembershipResolver _reference;

        public SessionAnalyzer(AnalysisOptions options, Action<string> diagnosticLog)
            : this(
                options,
                new NativeSessionDataSource(diagnosticLog),
                new ReferenceMembershipResolver(diagnosticLog))
        {
            if (String.IsNullOrWhiteSpace(_options.LocalMachineSid))
            {
                try
                {
                    _options.LocalMachineSid =
                        LocalMachineSidResolver.GetAccountDomainSid();
                }
                catch (NativeCallException exception)
                {
                    if (diagnosticLog != null)
                    {
                        diagnosticLog(exception.Message);
                    }
                }
                catch (InvalidOperationException exception)
                {
                    if (diagnosticLog != null)
                    {
                        diagnosticLog(exception.Message);
                    }
                }
            }
        }

        internal SessionAnalyzer(
            AnalysisOptions options,
            ISessionDataSource sessions,
            IReferenceMembershipResolver reference)
        {
            _options = options ?? throw new ArgumentNullException("options");
            _sessions = sessions ?? throw new ArgumentNullException("sessions");
            _reference = reference ?? throw new ArgumentNullException("reference");
        }

        public IReadOnlyCollection<LogonSessionSnapshot> EnumerateSessions(
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            IReadOnlyCollection<LogonSessionSnapshot> sessions =
                _sessions.EnumerateSessions();
            cancellationToken.ThrowIfCancellationRequested();
            return sessions;
        }

        public SessionAnalysisResult AnalyzeSession(
            LUID logonId,
            SessionTriggerContext trigger,
            CancellationToken cancellationToken)
        {
            Stopwatch stopwatch = Stopwatch.StartNew();
            SessionAnalysisResult result = CreateResult(trigger);

            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                LogonSessionSnapshot session = _sessions.GetSession(logonId);
                if (session == null)
                {
                    return Fail(
                        result,
                        AnalysisVerdict.Unknown,
                        AnalysisReason.SessionExpiredBeforeAnalysis,
                        "SessionNotFound",
                        "The logon session expired before it could be analyzed.");
                }

                result.Session = session;
                if (!_options.EnabledLogonTypes.Contains(session.LogonType))
                {
                    return Skip(
                        result,
                        AnalysisReason.UnsupportedLogonType,
                        "Logon type " + session.LogonType + " is disabled by policy.");
                }

                if (IsExcluded(session))
                {
                    return Skip(
                        result,
                        AnalysisReason.ExcludedByPolicy,
                        "The session is excluded by configured identity policy.");
                }

                if (!String.Equals(
                    session.AuthenticationPackage,
                    "Kerberos",
                    StringComparison.OrdinalIgnoreCase))
                {
                    return Skip(
                        result,
                        AnalysisReason.NonKerberosAuthenticationPackage,
                        "The LSA authentication package is not Kerberos.");
                }

                cancellationToken.ThrowIfCancellationRequested();
                IReadOnlyList<TokenGroupInfo> allTokenGroups =
                    _sessions.GetTokenGroups(logonId);
                foreach (TokenGroupInfo group in allTokenGroups)
                {
                    result.TokenGroups.Add(group);
                }

                result.TokenGroupCount = allTokenGroups.Count;
                result.PowerfulOnlyEnabled = _options.PowerfulOnly.Enabled;
                if (_options.PowerfulOnly.Enabled)
                {
                    PowerfulSessionClassification classification =
                        PowerfulSessionClassifier.Classify(
                            session.UserSid,
                            allTokenGroups,
                            _options.PowerfulOnly);
                    result.PowerfulSession = classification.IsPowerful;
                    result.PowerfulMatchReason = classification.MatchReason;

                    if (!classification.IsPowerful.HasValue)
                    {
                        return Fail(
                            result,
                            AnalysisVerdict.Unknown,
                            AnalysisReason.PowerfulClassificationFailed,
                            "PowerfulClassificationFailed",
                            classification.MatchReason);
                    }

                    if (!classification.IsPowerful.Value)
                    {
                        return Skip(
                            result,
                            AnalysisReason.NotPowerful,
                            classification.MatchReason);
                    }
                }

                cancellationToken.ThrowIfCancellationRequested();
                MembershipResult reference = _reference.Resolve(session);
                result.ReferenceProvider = reference.Source;
                result.ReferenceSucceeded = reference.Success;
                result.ReferenceError = reference.Error;
                result.AccountExists = reference.AccountExists;
                result.AccountEnabled = reference.AccountEnabled;
                result.ReferenceGroupCount = reference.DomainGroupSids.Count;

                if (!reference.Success)
                {
                    return Fail(
                        result,
                        AnalysisVerdict.Unknown,
                        AnalysisReason.LdapFallbackFailed,
                        "ReferenceUnavailable",
                        reference.Error);
                }

                List<TokenGroupInfo> comparableTokenGroups = allTokenGroups
                    .Where(group => IsComparableDomainSid(group.Sid))
                    .ToList();
                IList<GroupComparison> comparisons = RuleEngine.BuildComparisons(
                    session,
                    comparableTokenGroups,
                    reference);
                foreach (GroupComparison comparison in comparisons)
                {
                    result.GroupComparisons.Add(comparison);
                }

                result.TokenOnlyGroupCount = comparisons.Count(
                    comparison => comparison.Kind == GroupComparisonKind.TokenOnly);
                result.ReferenceOnlyGroupCount = comparisons.Count(
                    comparison => comparison.Kind == GroupComparisonKind.ReferenceOnly);

                IList<RuleMatch> ruleMatches = RuleEngine.Evaluate(
                    session,
                    result.Trigger,
                    comparableTokenGroups,
                    reference,
                    comparisons);
                foreach (RuleMatch ruleMatch in ruleMatches)
                {
                    result.RuleMatches.Add(ruleMatch);
                }

                result.ProcessingStatus = ProcessingStatus.Completed;
                result.Reason = AnalysisReason.None;
                result.Verdict = ruleMatches.Any(rule => rule.IsSuspicious)
                    ? AnalysisVerdict.Suspicious
                    : AnalysisVerdict.Clean;
                return result;
            }
            catch (NativeCallException exception)
            {
                return Fail(
                    result,
                    AnalysisVerdict.Unknown,
                    AnalysisReason.TokenAcquisitionFailed,
                    "0x" + exception.StatusCode.ToString("X8"),
                    exception.Message);
            }
            catch (Win32Exception exception)
            {
                return Fail(
                    result,
                    AnalysisVerdict.Unknown,
                    AnalysisReason.TokenAcquisitionFailed,
                    exception.NativeErrorCode.ToString(),
                    exception.Message);
            }
            catch (ArgumentException exception)
            {
                return Fail(
                    result,
                    AnalysisVerdict.Error,
                    AnalysisReason.InternalError,
                    exception.GetType().Name,
                    exception.Message);
            }
            catch (InvalidOperationException exception)
            {
                return Fail(
                    result,
                    AnalysisVerdict.Error,
                    AnalysisReason.InternalError,
                    exception.GetType().Name,
                    exception.Message);
            }
            finally
            {
                stopwatch.Stop();
                result.DurationMilliseconds = stopwatch.ElapsedMilliseconds;
            }
        }

        private SessionAnalysisResult CreateResult(SessionTriggerContext trigger)
        {
            return new SessionAnalysisResult
            {
                ProductVersion = typeof(SessionAnalyzer).Assembly.GetName().Version.ToString(),
                ComputerName = Environment.MachineName,
                BootInstanceId = BootInstanceIdProvider.Current,
                Trigger = trigger ?? new SessionTriggerContext
                {
                    Source = TriggerSource.PeriodicReconciliation
                },
                PowerfulOnlyEnabled = _options.PowerfulOnly.Enabled,
                ProcessingStatus = ProcessingStatus.Failed,
                Verdict = AnalysisVerdict.Error,
                Reason = AnalysisReason.InternalError
            };
        }

        private bool IsExcluded(LogonSessionSnapshot session)
        {
            return _options.ExcludedUserSids.Contains(session.UserSid ?? String.Empty) ||
                _options.ExcludedAccountNames.Contains(session.AccountName ?? String.Empty) ||
                _options.ExcludedAccountNames.Contains(session.UserName ?? String.Empty) ||
                _options.ExcludedDomains.Contains(session.LogonDomain ?? String.Empty) ||
                _options.ExcludedDomains.Contains(session.DnsDomainName ?? String.Empty);
        }

        private bool IsComparableDomainSid(string sid)
        {
            if (String.IsNullOrWhiteSpace(sid) ||
                !sid.StartsWith("S-1-5-21-", StringComparison.Ordinal) ||
                String.Equals(
                    sid,
                    "S-1-5-21-0-0-0-497",
                    StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return String.IsNullOrWhiteSpace(_options.LocalMachineSid) ||
                !sid.StartsWith(
                    _options.LocalMachineSid.TrimEnd('-') + "-",
                    StringComparison.OrdinalIgnoreCase);
        }

        private static SessionAnalysisResult Skip(
            SessionAnalysisResult result,
            AnalysisReason reason,
            string message)
        {
            result.ProcessingStatus = ProcessingStatus.Skipped;
            result.Verdict = AnalysisVerdict.NotEvaluated;
            result.Reason = reason;
            result.ErrorMessage = message;
            return result;
        }

        private static SessionAnalysisResult Fail(
            SessionAnalysisResult result,
            AnalysisVerdict verdict,
            AnalysisReason reason,
            string errorCode,
            string message)
        {
            result.ProcessingStatus = ProcessingStatus.Failed;
            result.Verdict = verdict;
            result.Reason = reason;
            result.ErrorCode = errorCode;
            result.ErrorMessage = message;
            return result;
        }
    }
}
