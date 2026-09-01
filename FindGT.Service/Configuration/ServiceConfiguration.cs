using System;
using System.Collections.Generic;
using FindGT.Core.Analysis;

namespace FindGT.Service.Configuration
{
    public sealed class ServiceConfiguration
    {
        public int SchemaVersion { get; set; }
        public int[] EnabledLogonTypes { get; set; }
        public bool AnalyzeExistingSessionsOnStart { get; set; }
        public int ReconciliationIntervalSeconds { get; set; }
        public QueueConfiguration Queue { get; set; }
        public int[] RetryDelaysMilliseconds { get; set; }
        public PowerfulOnlyConfiguration PowerfulOnly { get; set; }
        public OutputConfiguration Output { get; set; }
        public ExclusionConfiguration Exclusions { get; set; }

        public static ServiceConfiguration CreateDefault()
        {
            return new ServiceConfiguration
            {
                SchemaVersion = 1,
                EnabledLogonTypes = new[] { 3, 10 },
                AnalyzeExistingSessionsOnStart = true,
                ReconciliationIntervalSeconds = 60,
                Queue = new QueueConfiguration
                {
                    Capacity = 1024,
                    WorkerCount = 1
                },
                RetryDelaysMilliseconds = new[] { 0, 250, 1000, 3000, 10000 },
                PowerfulOnly = new PowerfulOnlyConfiguration
                {
                    Enabled = false,
                    PrivilegedUserRids = new uint[] { 500 },
                    PrivilegedGroupRids = new uint[] { 512, 518, 519 },
                    ExactSids = new[] { "S-1-5-32-544" },
                    AdditionalSids = new string[0]
                },
                Output = new OutputConfiguration
                {
                    OperationalEventLog = new OperationalOutputConfiguration
                    {
                        Enabled = true
                    },
                    SecurityEventLog = new SecurityOutputConfiguration
                    {
                        Mode = "SuspiciousOnly"
                    },
                    Json = new JsonOutputConfiguration
                    {
                        Enabled = false,
                        Directory = @"%ProgramData%\FindGT\Logs"
                    }
                },
                Exclusions = new ExclusionConfiguration
                {
                    UserSids = new string[0],
                    AccountNames = new string[0],
                    Domains = new string[0]
                }
            };
        }

        public AnalysisOptions ToAnalysisOptions()
        {
            AnalysisOptions options = new AnalysisOptions();
            options.EnabledLogonTypes.Clear();
            foreach (int logonType in EnabledLogonTypes)
            {
                options.EnabledLogonTypes.Add((uint)logonType);
            }

            options.PowerfulOnly.Enabled = PowerfulOnly.Enabled;
            Replace(options.PowerfulOnly.PrivilegedUserRids, PowerfulOnly.PrivilegedUserRids);
            Replace(options.PowerfulOnly.PrivilegedGroupRids, PowerfulOnly.PrivilegedGroupRids);
            Replace(options.PowerfulOnly.ExactSids, PowerfulOnly.ExactSids);
            Replace(options.PowerfulOnly.AdditionalSids, PowerfulOnly.AdditionalSids);
            Replace(options.ExcludedUserSids, Exclusions.UserSids);
            Replace(options.ExcludedAccountNames, Exclusions.AccountNames);
            Replace(options.ExcludedDomains, Exclusions.Domains);
            return options;
        }

        private static void Replace<T>(ISet<T> target, IEnumerable<T> values)
        {
            target.Clear();
            foreach (T value in values)
            {
                target.Add(value);
            }
        }
    }

    public sealed class QueueConfiguration
    {
        public int Capacity { get; set; }
        public int WorkerCount { get; set; }
    }

    public sealed class PowerfulOnlyConfiguration
    {
        public bool Enabled { get; set; }
        public uint[] PrivilegedUserRids { get; set; }
        public uint[] PrivilegedGroupRids { get; set; }
        public string[] ExactSids { get; set; }
        public string[] AdditionalSids { get; set; }
    }

    public sealed class OutputConfiguration
    {
        public OperationalOutputConfiguration OperationalEventLog { get; set; }
        public SecurityOutputConfiguration SecurityEventLog { get; set; }
        public JsonOutputConfiguration Json { get; set; }
    }

    public sealed class OperationalOutputConfiguration
    {
        public bool Enabled { get; set; }
    }

    public sealed class SecurityOutputConfiguration
    {
        public string Mode { get; set; }
    }

    public sealed class JsonOutputConfiguration
    {
        public bool Enabled { get; set; }
        public string Directory { get; set; }
    }

    public sealed class ExclusionConfiguration
    {
        public string[] UserSids { get; set; }
        public string[] AccountNames { get; set; }
        public string[] Domains { get; set; }
    }
}
