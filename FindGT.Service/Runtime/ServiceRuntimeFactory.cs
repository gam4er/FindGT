using System;
using System.IO;
using FindGT.Core.Analysis;
using FindGT.Eventing;
using FindGT.Service.Configuration;
using FindGT.Service.Logging;

namespace FindGT.Service.Runtime
{
    internal static class ServiceRuntimeFactory
    {
        internal static FindGtServiceRuntime Create(
            string configurationPath,
            bool console)
        {
            ServiceConfigurationLoader loader = new ServiceConfigurationLoader();
            ConfigurationLoadResult configuration = loader.Load(
                configurationPath);
            IServiceEventSink sink;
            if (console)
            {
                sink = new BootstrapEventSink(true);
            }
            else
            {
                SecuritySinkMode securityMode;
                if (!AuthzSecurityEventSink.TryParseMode(
                    configuration.Configuration.Output.SecurityEventLog.Mode,
                    out securityMode))
                {
                    securityMode = SecuritySinkMode.SuspiciousOnly;
                }

                sink = new CompositeServiceEventSink(
                    configuration.Configuration.Output.OperationalEventLog.Enabled,
                    securityMode,
                    configuration.Configuration.Output.Json.Enabled,
                    configuration.Configuration.Output.Json.Directory);
            }
            SessionAnalyzer analyzer = new SessionAnalyzer(
                configuration.Configuration.ToAnalysisOptions(),
                delegate(string message)
                {
                    sink.WriteServiceEvent(new ServiceEventRecord
                    {
                        EventId = ServiceEventIds.SessionAnalysisError,
                        Level = ServiceEventLevel.Warning,
                        HealthState = ServiceHealthState.Healthy,
                        Message = message
                    });
                });
            string bookmarkPath = System.IO.Path.Combine(
                Environment.GetFolderPath(
                    Environment.SpecialFolder.CommonApplicationData),
                "FindGT",
                "State",
                "Security.bookmark.xml");

            return new FindGtServiceRuntime(
                configuration,
                analyzer,
                sink,
                new EventSubscriptionFactory(),
                new EventBookmarkStore(bookmarkPath));
        }
    }
}
