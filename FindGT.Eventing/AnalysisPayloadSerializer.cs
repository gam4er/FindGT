using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Script.Serialization;
using FindGT.Core;

namespace FindGT.Eventing
{
    internal static class AnalysisPayloadSerializer
    {
        private const int MaximumEventCharacters = 30000;

        internal static string SerializeAnalysis(SessionAnalysisResult result)
        {
            if (result == null)
            {
                throw new ArgumentNullException("result");
            }

            string payload = Serialize(BuildAnalysis(result, Int32.MaxValue));
            if (payload.Length <= MaximumEventCharacters)
            {
                return payload;
            }

            result.PayloadTruncated = true;
            payload = Serialize(BuildAnalysis(result, 32));
            if (payload.Length <= MaximumEventCharacters)
            {
                return payload;
            }

            Dictionary<string, object> minimal = BuildSummary(result);
            minimal["PayloadTruncated"] = true;
            minimal["ErrorMessage"] = Truncate(result.ErrorMessage, 2048);
            payload = Serialize(minimal);
            if (payload.Length <= MaximumEventCharacters)
            {
                return payload;
            }

            return Serialize(new Dictionary<string, object>
            {
                ["SchemaVersion"] = result.SchemaVersion,
                ["AnalysisId"] = result.AnalysisId.ToString("D"),
                ["Verdict"] = result.Verdict.ToString(),
                ["PayloadTruncated"] = true
            });
        }

        internal static string SerializeAnalysisForJson(
            SessionAnalysisResult result)
        {
            if (result == null)
            {
                throw new ArgumentNullException("result");
            }

            return Serialize(BuildAnalysis(result, Int32.MaxValue));
        }

        internal static string SerializeSecurity(SessionAnalysisResult result)
        {
            Dictionary<string, object> payload = BuildSummary(result);
            payload["SourceAddress"] = result.Trigger?.IpAddress;
            payload["SourcePort"] = result.Trigger?.IpPort;
            payload["OperationalCorrelationId"] = result.AnalysisId.ToString("D");
            payload["SampleTokenOnlySids"] = result.GroupComparisons
                .Where(comparison =>
                    comparison.Kind == GroupComparisonKind.TokenOnly)
                .Select(comparison => comparison.Sid)
                .Take(10)
                .ToArray();
            string serialized = Serialize(payload);
            if (serialized.Length <= MaximumEventCharacters)
            {
                return serialized;
            }

            return Serialize(new Dictionary<string, object>
            {
                ["SchemaVersion"] = result.SchemaVersion,
                ["AnalysisId"] = result.AnalysisId.ToString("D"),
                ["Verdict"] = result.Verdict.ToString(),
                ["PayloadTruncated"] = true
            });
        }

        internal static string SerializeServiceEvent(ServiceEventRecord record)
        {
            return Serialize(new Dictionary<string, object>
            {
                ["SchemaVersion"] = 1,
                ["TimestampUtc"] = record.TimestampUtc.ToString("O"),
                ["EventId"] = record.EventId,
                ["Level"] = record.Level.ToString(),
                ["HealthState"] = record.HealthState.ToString(),
                ["Message"] = Truncate(record.Message, 4096),
                ["Properties"] = record.Properties
            });
        }

        private static Dictionary<string, object> BuildAnalysis(
            SessionAnalysisResult result,
            int collectionLimit)
        {
            Dictionary<string, object> payload = BuildSummary(result);
            payload["ComputerName"] = result.ComputerName;
            payload["BootInstanceId"] = result.BootInstanceId.ToString("D");
            payload["TimestampUtc"] = result.TimestampUtc.ToString("O");
            payload["DurationMilliseconds"] = result.DurationMilliseconds;
            payload["RetryCount"] = result.RetryCount;
            payload["ReferenceError"] = result.ReferenceError;
            payload["ErrorCode"] = result.ErrorCode;
            payload["ErrorMessage"] = result.ErrorMessage;
            payload["AccountExists"] = result.AccountExists;
            payload["AccountEnabled"] = result.AccountEnabled;
            payload["PayloadTruncated"] = result.PayloadTruncated;
            payload["Trigger"] = BuildTrigger(result.Trigger);
            payload["Session"] = BuildSession(result.Session);
            payload["TokenGroups"] = result.TokenGroups
                .Take(collectionLimit)
                .Select(group => new Dictionary<string, object>
                {
                    ["Sid"] = group.Sid,
                    ["Attributes"] = "0x" + group.Attributes.ToString("X8")
                })
                .ToArray();
            payload["GroupComparisons"] = result.GroupComparisons
                .Take(collectionLimit)
                .Select(comparison => new Dictionary<string, object>
                {
                    ["Sid"] = comparison.Sid,
                    ["Name"] = comparison.Name,
                    ["Kind"] = comparison.Kind.ToString(),
                    ["TokenAttributes"] = comparison.TokenAttributes.HasValue
                        ? "0x" + comparison.TokenAttributes.Value.ToString("X8")
                        : null,
                    ["IsUserSid"] = comparison.IsUserSid
                })
                .ToArray();
            payload["Rules"] = result.RuleMatches
                .Take(collectionLimit)
                .Select(rule => new Dictionary<string, object>
                {
                    ["RuleId"] = rule.RuleId,
                    ["Severity"] = rule.Severity.ToString(),
                    ["Confidence"] = rule.Confidence.ToString(),
                    ["IsSuspicious"] = rule.IsSuspicious,
                    ["Description"] = rule.Description,
                    ["Evidence"] = rule.Evidence
                })
                .ToArray();
            return payload;
        }

        private static Dictionary<string, object> BuildSummary(
            SessionAnalysisResult result)
        {
            return new Dictionary<string, object>
            {
                ["SchemaVersion"] = result.SchemaVersion,
                ["ProductVersion"] = result.ProductVersion,
                ["AnalysisId"] = result.AnalysisId.ToString("D"),
                ["LogonId"] = result.Session == null
                    ? result.Trigger?.TargetLogonId?.ToString()
                    : result.Session.LogonId.ToString(),
                ["LogonType"] = result.Session?.LogonType,
                ["UserSid"] = result.Session?.UserSid,
                ["UserName"] = result.Session?.UserName,
                ["Domain"] = result.Session?.LogonDomain,
                ["Verdict"] = result.Verdict.ToString(),
                ["ProcessingStatus"] = result.ProcessingStatus.ToString(),
                ["Reason"] = result.Reason.ToString(),
                ["RuleIds"] = result.RuleMatches
                    .Select(rule => rule.RuleId)
                    .Distinct(StringComparer.Ordinal)
                    .ToArray(),
                ["ReferenceProvider"] = result.ReferenceProvider,
                ["ReferenceSucceeded"] = result.ReferenceSucceeded,
                ["TokenGroupCount"] = result.TokenGroupCount,
                ["ReferenceGroupCount"] = result.ReferenceGroupCount,
                ["TokenOnlyGroupCount"] = result.TokenOnlyGroupCount,
                ["ReferenceOnlyGroupCount"] = result.ReferenceOnlyGroupCount,
                ["PowerfulOnlyEnabled"] = result.PowerfulOnlyEnabled,
                ["PowerfulSession"] = result.PowerfulSession,
                ["PowerfulMatchReason"] = result.PowerfulMatchReason,
                ["PayloadTruncated"] = result.PayloadTruncated
            };
        }

        private static object BuildTrigger(SessionTriggerContext trigger)
        {
            if (trigger == null)
            {
                return null;
            }

            return new Dictionary<string, object>
            {
                ["Source"] = trigger.Source.ToString(),
                ["EventRecordId"] = trigger.EventRecordId,
                ["EventTimeUtc"] = trigger.EventTimeUtc?.ToString("O"),
                ["TargetLogonId"] = trigger.TargetLogonId?.ToString(),
                ["TargetUserSid"] = trigger.TargetUserSid,
                ["TargetUserName"] = trigger.TargetUserName,
                ["TargetDomainName"] = trigger.TargetDomainName,
                ["LogonType"] = trigger.LogonType,
                ["AuthenticationPackage"] = trigger.AuthenticationPackage,
                ["LogonProcessName"] = trigger.LogonProcessName,
                ["WorkstationName"] = trigger.WorkstationName,
                ["IpAddress"] = trigger.IpAddress,
                ["IpPort"] = trigger.IpPort,
                ["ProcessId"] = trigger.ProcessId,
                ["ProcessName"] = trigger.ProcessName,
                ["LogonGuid"] = trigger.LogonGuid?.ToString("D"),
                ["LinkedLogonId"] = trigger.LinkedLogonId?.ToString()
            };
        }

        private static object BuildSession(LogonSessionSnapshot session)
        {
            if (session == null)
            {
                return null;
            }

            return new Dictionary<string, object>
            {
                ["LogonId"] = session.LogonId.ToString(),
                ["UserName"] = session.UserName,
                ["AccountName"] = session.AccountName,
                ["LogonDomain"] = session.LogonDomain,
                ["DnsDomainName"] = session.DnsDomainName,
                ["Upn"] = session.Upn,
                ["UserSid"] = session.UserSid,
                ["LogonType"] = session.LogonType,
                ["AuthenticationPackage"] = session.AuthenticationPackage,
                ["SessionId"] = session.SessionId,
                ["LogonTimeUtc"] = session.LogonTimeUtc?.ToString("O"),
                ["LogonServer"] = session.LogonServer,
                ["UserFlags"] = "0x" + session.UserFlags.ToString("X8")
            };
        }

        private static string Serialize(object value)
        {
            JavaScriptSerializer serializer = new JavaScriptSerializer
            {
                MaxJsonLength = 1024 * 1024,
                RecursionLimit = 32
            };
            return serializer.Serialize(value);
        }

        private static string Truncate(string value, int maximumLength)
        {
            if (String.IsNullOrEmpty(value) || value.Length <= maximumLength)
            {
                return value;
            }

            return value.Substring(0, maximumLength);
        }
    }
}
