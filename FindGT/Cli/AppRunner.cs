using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Threading;
using FindGT.Core;
using FindGT.Core.Analysis;
using FindGT.Membership;
using FindGT.Reporting;

namespace FindGT.Cli
{
    internal static class AppRunner
    {
        public static bool EnsureSystem()
        {
            if (!SystemContext.IsHighIntegrity())
            {
                Ui.Error("Требуется запуск от администратора (high integrity).");
                return false;
            }

            if (SystemContext.IsLocalSystem())
            {
                Ui.Info("Уже SYSTEM — эскалация не требуется.");
                return true;
            }

            if (!SystemContext.TryImpersonateLocalSystem())
            {
                Ui.Error("Не удалось повысить привилегии до SYSTEM.");
                return false;
            }

            Ui.Success("Повышены привилегии до SYSTEM.");
            return true;
        }

        public static int RunReport(bool verbose, bool html)
        {
            Action<string> diagnosticLog = verbose
                ? new Action<string>(Ui.Warn)
                : delegate { };
            SessionAnalyzer analyzer = new SessionAnalyzer(
                AnalysisOptions.ForCli(),
                diagnosticLog);
            IReadOnlyCollection<LogonSessionSnapshot> sessions;

            try
            {
                sessions = analyzer.EnumerateSessions(CancellationToken.None);
            }
            catch (NativeCallException exception)
            {
                Ui.Error(exception.Message);
                return 1;
            }
            catch (Win32Exception exception)
            {
                Ui.Error(exception.Message);
                return 1;
            }
            catch (InvalidOperationException exception)
            {
                Ui.Error(exception.Message);
                return 1;
            }

            SpectreReporter reporter = new SpectreReporter(verbose, html);
            reporter.Header();
            foreach (LogonSessionSnapshot session in sessions.Where(
                candidate => String.Equals(
                    candidate.AuthenticationPackage,
                    "Kerberos",
                    StringComparison.OrdinalIgnoreCase)))
            {
                SessionAnalysisResult result = analyzer.AnalyzeSession(
                    session.LogonId,
                    SessionTriggerContext.ForCli(),
                    CancellationToken.None);
                reporter.RenderSession(ToReport(result));
            }

            reporter.Finish();
            return 0;
        }

        private static SessionReport ToReport(SessionAnalysisResult result)
        {
            SessionReport report = new SessionReport
            {
                Luid = result.Session == null
                    ? result.Trigger.TargetLogonId?.ToString()
                    : result.Session.LogonId.ToString(),
                UserSid = result.Session == null ? null : result.Session.UserSid,
                UserName = result.Session == null ? null : result.Session.UserName,
                AuthPackage = result.Session == null
                    ? null
                    : result.Session.AuthenticationPackage,
                ReferenceSource = result.ReferenceProvider,
                ReferenceOk = result.ReferenceSucceeded,
                ReferenceError = result.ReferenceError ?? result.ErrorMessage,
                TokenDomainGroupCount = result.TokenOnlyGroupCount +
                    result.GroupComparisons.Count(
                        comparison => comparison.Kind == GroupComparisonKind.Match),
                ReferenceDomainGroupCount = result.ReferenceGroupCount,
                Verdict = result.Verdict,
                Reason = result.Reason,
                RuleIds = result.RuleMatches
                    .Select(rule => rule.RuleId)
                    .Distinct(StringComparer.Ordinal)
                    .ToList()
            };

            foreach (GroupComparison comparison in result.GroupComparisons)
            {
                string name = comparison.Name;
                bool isUser = comparison.IsUserSid;
                if (String.IsNullOrWhiteSpace(name))
                {
                    bool resolvedAsUser;
                    SidUtil.Classify(
                        comparison.Sid,
                        out name,
                        out resolvedAsUser);
                    isUser = isUser || resolvedAsUser;
                }

                report.Rows.Add(new DiffRow
                {
                    Sid = comparison.Sid,
                    Name = name,
                    Kind = MapKind(comparison.Kind),
                    IsUserSid = isUser,
                    Comment = comparison.Kind.ToString()
                });
            }

            return report;
        }

        private static DiffKind MapKind(GroupComparisonKind kind)
        {
            switch (kind)
            {
                case GroupComparisonKind.TokenOnly:
                    return DiffKind.InSessionNotInReference;
                case GroupComparisonKind.ReferenceOnly:
                    return DiffKind.InReferenceNotInSession;
                default:
                    return DiffKind.Match;
            }
        }
    }
}
