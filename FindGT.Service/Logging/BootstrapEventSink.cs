using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Security;
using FindGT.Core;
using FindGT.Eventing;

namespace FindGT.Service.Logging
{
    internal sealed class BootstrapEventSink : IServiceEventSink
    {
        private const string SourceName = "FindGT.Service";
        private readonly bool _console;

        internal BootstrapEventSink(bool console)
        {
            _console = console;
        }

        public SinkWriteResult WriteAnalysis(SessionAnalysisResult result)
        {
            if (result == null)
            {
                throw new ArgumentNullException("result");
            }

            int eventId;
            EventLogEntryType entryType;
            switch (result.Verdict)
            {
                case AnalysisVerdict.Clean:
                    eventId = ServiceEventIds.SessionAnalysisClean;
                    entryType = EventLogEntryType.Information;
                    break;
                case AnalysisVerdict.Suspicious:
                    eventId = ServiceEventIds.SessionAnalysisSuspicious;
                    entryType = EventLogEntryType.Warning;
                    break;
                case AnalysisVerdict.Unknown:
                    eventId = ServiceEventIds.SessionAnalysisUnknown;
                    entryType = EventLogEntryType.Warning;
                    break;
                case AnalysisVerdict.NotEvaluated:
                    eventId = result.Reason == AnalysisReason.NotPowerful
                        ? ServiceEventIds.SessionSkippedNotPowerful
                        : ServiceEventIds.SessionSkippedByPolicy;
                    entryType = EventLogEntryType.Information;
                    break;
                default:
                    eventId = ServiceEventIds.SessionAnalysisError;
                    entryType = EventLogEntryType.Error;
                    break;
            }

            string message =
                "AnalysisId=" + result.AnalysisId +
                "; Verdict=" + result.Verdict +
                "; LogonId=" +
                (result.Session == null
                    ? result.Trigger?.TargetLogonId?.ToString()
                    : result.Session.LogonId.ToString()) +
                "; Rules=" + String.Join(
                    ",",
                    result.RuleMatches.Select(rule => rule.RuleId).Distinct());
            bool persisted = Write(message, entryType, eventId);
            return new SinkWriteResult
            {
                OperationalPersisted = persisted,
                SecurityPersisted = false,
                Error = persisted
                    ? null
                    : "Bootstrap Application event source is unavailable."
            };
        }

        public bool WriteServiceEvent(ServiceEventRecord record)
        {
            if (record == null)
            {
                throw new ArgumentNullException("record");
            }

            EventLogEntryType entryType = record.Level == ServiceEventLevel.Error
                ? EventLogEntryType.Error
                : (record.Level == ServiceEventLevel.Warning
                    ? EventLogEntryType.Warning
                    : EventLogEntryType.Information);
            return Write(record.Message, entryType, record.EventId);
        }

        public void Dispose()
        {
        }

        private bool Write(
            string message,
            EventLogEntryType entryType,
            int eventId)
        {
            if (_console)
            {
                Console.WriteLine(
                    DateTime.UtcNow.ToString("O") + " [" + eventId + "] " + message);
                return true;
            }

            try
            {
                if (!EventLog.SourceExists(SourceName))
                {
                    Trace.TraceError(
                        "Event source {0} is not registered: {1}",
                        SourceName,
                        message);
                    return false;
                }

                EventLog.WriteEntry(SourceName, message, entryType, eventId);
                return true;
            }
            catch (SecurityException exception)
            {
                Trace.TraceError(exception.ToString());
            }
            catch (Win32Exception exception)
            {
                Trace.TraceError(exception.ToString());
            }
            catch (InvalidOperationException exception)
            {
                Trace.TraceError(exception.ToString());
            }

            return false;
        }
    }
}
