using System;
using System.Collections.Generic;
using FindGT.Core;

namespace FindGT.Eventing
{
    public sealed class CompositeServiceEventSink :
        IServiceEventSink,
        IServiceEventSinkStatus
    {
        private readonly object _sync = new object();
        private readonly ManifestEventWriter _operational;
        private readonly JsonResultSink _json;
        private readonly AuthzSecurityEventSink _security;
        private bool _disposed;

        public CompositeServiceEventSink(
            bool operationalEnabled,
            SecuritySinkMode securityMode,
            bool jsonEnabled,
            string jsonDirectory)
        {
            if (!operationalEnabled && !jsonEnabled)
            {
                throw new ArgumentException(
                    "At least one full-result sink must be enabled.");
            }

            _operational = operationalEnabled
                ? new ManifestEventWriter()
                : null;
            _json = jsonEnabled
                ? new JsonResultSink(jsonDirectory)
                : null;
            _security = new AuthzSecurityEventSink(securityMode);
        }

        public string SecurityInitializationError
        {
            get { return _security.InitializationError; }
        }

        public SinkWriteResult WriteAnalysis(SessionAnalysisResult result)
        {
            if (result == null)
            {
                throw new ArgumentNullException("result");
            }

            lock (_sync)
            {
                ThrowIfDisposed();
                List<string> errors = new List<string>();
                bool operationalPersisted = false;
                string payload = AnalysisPayloadSerializer.SerializeAnalysis(result);

                if (_operational != null)
                {
                    string operationalError;
                    operationalPersisted = _operational.Write(
                        AnalysisEventId(result),
                        AnalysisLevel(result),
                        payload,
                        out operationalError);
                    AddError(errors, operationalError);
                }

                if (_json != null)
                {
                    string jsonError;
                    bool jsonPersisted = _json.WriteAnalysis(
                        result,
                        out jsonError);
                    operationalPersisted = operationalPersisted || jsonPersisted;
                    AddError(errors, jsonError);
                }

                bool securityPersisted = true;
                if (_security.ShouldWrite(result))
                {
                    string securityError;
                    securityPersisted = _security.Write(
                        result,
                        AnalysisPayloadSerializer.SerializeSecurity(result),
                        out securityError);
                    AddError(errors, securityError);
                }

                return new SinkWriteResult
                {
                    OperationalPersisted = operationalPersisted,
                    SecurityPersisted = securityPersisted,
                    Error = errors.Count == 0
                        ? null
                        : String.Join(" | ", errors)
                };
            }
        }

        public bool WriteServiceEvent(ServiceEventRecord record)
        {
            if (record == null)
            {
                throw new ArgumentNullException("record");
            }

            lock (_sync)
            {
                ThrowIfDisposed();
                bool persisted = false;
                if (_operational != null)
                {
                    string error;
                    persisted = _operational.Write(
                        record.EventId,
                        record.Level,
                        AnalysisPayloadSerializer.SerializeServiceEvent(record),
                        out error);
                }

                if (_json != null)
                {
                    string error;
                    persisted = _json.WriteServiceEvent(record, out error) ||
                        persisted;
                }

                return persisted;
            }
        }

        public void Dispose()
        {
            lock (_sync)
            {
                if (_disposed)
                {
                    return;
                }

                _disposed = true;
                _security.Dispose();
                _json?.Dispose();
                _operational?.Dispose();
            }
        }

        private static int AnalysisEventId(SessionAnalysisResult result)
        {
            switch (result.Verdict)
            {
                case AnalysisVerdict.Clean:
                    return ServiceEventIds.SessionAnalysisClean;
                case AnalysisVerdict.Suspicious:
                    return ServiceEventIds.SessionAnalysisSuspicious;
                case AnalysisVerdict.Unknown:
                    return ServiceEventIds.SessionAnalysisUnknown;
                case AnalysisVerdict.NotEvaluated:
                    return result.Reason == AnalysisReason.NotPowerful
                        ? ServiceEventIds.SessionSkippedNotPowerful
                        : ServiceEventIds.SessionSkippedByPolicy;
                default:
                    return ServiceEventIds.SessionAnalysisError;
            }
        }

        private static ServiceEventLevel AnalysisLevel(
            SessionAnalysisResult result)
        {
            switch (result.Verdict)
            {
                case AnalysisVerdict.Suspicious:
                case AnalysisVerdict.Unknown:
                    return ServiceEventLevel.Warning;
                case AnalysisVerdict.Error:
                    return ServiceEventLevel.Error;
                default:
                    return ServiceEventLevel.Information;
            }
        }

        private static void AddError(
            ICollection<string> errors,
            string error)
        {
            if (!String.IsNullOrWhiteSpace(error))
            {
                errors.Add(error);
            }
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(
                    typeof(CompositeServiceEventSink).FullName);
            }
        }
    }
}
