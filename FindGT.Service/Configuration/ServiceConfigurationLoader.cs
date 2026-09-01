using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Web.Script.Serialization;

namespace FindGT.Service.Configuration
{
    public sealed class ConfigurationLoadResult
    {
        public ServiceConfiguration Configuration { get; set; }
        public string Path { get; set; }
        public bool IsValid { get; set; }
        public bool UsedDefaults { get; set; }
        public string Error { get; set; }
    }

    public sealed class ServiceConfigurationLoader
    {
        private static readonly HashSet<int> SupportedLogonTypes =
            new HashSet<int> { 2, 3, 4, 5, 9, 10 };

        public static string DefaultPath
        {
            get
            {
                return System.IO.Path.Combine(
                    Environment.GetFolderPath(
                        Environment.SpecialFolder.CommonApplicationData),
                    "FindGT",
                    "Config",
                    "FindGT.settings.json");
            }
        }

        public ConfigurationLoadResult Load(string path)
        {
            string resolvedPath = System.IO.Path.GetFullPath(
                Environment.ExpandEnvironmentVariables(
                    String.IsNullOrWhiteSpace(path) ? DefaultPath : path));
            if (!File.Exists(resolvedPath))
            {
                return new ConfigurationLoadResult
                {
                    Configuration = ServiceConfiguration.CreateDefault(),
                    Path = resolvedPath,
                    IsValid = true,
                    UsedDefaults = true,
                    Error = "Configuration file not found; safe defaults are active."
                };
            }

            try
            {
                string json = File.ReadAllText(resolvedPath);
                JavaScriptSerializer serializer = new JavaScriptSerializer
                {
                    MaxJsonLength = 1024 * 1024,
                    RecursionLimit = 32
                };
                ServiceConfiguration configuration =
                    serializer.Deserialize<ServiceConfiguration>(json);
                IList<string> errors = Validate(configuration);
                if (errors.Count != 0)
                {
                    return Invalid(resolvedPath, String.Join("; ", errors));
                }

                return new ConfigurationLoadResult
                {
                    Configuration = configuration,
                    Path = resolvedPath,
                    IsValid = true,
                    UsedDefaults = false
                };
            }
            catch (IOException exception)
            {
                return Invalid(resolvedPath, exception.Message);
            }
            catch (UnauthorizedAccessException exception)
            {
                return Invalid(resolvedPath, exception.Message);
            }
            catch (InvalidOperationException exception)
            {
                return Invalid(resolvedPath, exception.Message);
            }
            catch (ArgumentException exception)
            {
                return Invalid(resolvedPath, exception.Message);
            }
        }

        internal static IList<string> Validate(ServiceConfiguration configuration)
        {
            List<string> errors = new List<string>();
            if (configuration == null)
            {
                errors.Add("Configuration root is null.");
                return errors;
            }

            if (configuration.SchemaVersion != 1)
            {
                errors.Add("SchemaVersion must be 1.");
            }

            if (configuration.EnabledLogonTypes == null ||
                configuration.EnabledLogonTypes.Length == 0)
            {
                errors.Add("EnabledLogonTypes must not be empty.");
            }
            else
            {
                foreach (int logonType in configuration.EnabledLogonTypes)
                {
                    if (!SupportedLogonTypes.Contains(logonType))
                    {
                        errors.Add(
                            "Unsupported logon type " +
                            logonType.ToString(CultureInfo.InvariantCulture) + ".");
                    }
                }

                if (configuration.EnabledLogonTypes.Distinct().Count() !=
                    configuration.EnabledLogonTypes.Length)
                {
                    errors.Add("EnabledLogonTypes contains duplicates.");
                }
            }

            if (configuration.ReconciliationIntervalSeconds < 10 ||
                configuration.ReconciliationIntervalSeconds > 86400)
            {
                errors.Add(
                    "ReconciliationIntervalSeconds must be between 10 and 86400.");
            }

            ValidateQueue(configuration.Queue, errors);
            ValidateRetryDelays(configuration.RetryDelaysMilliseconds, errors);
            ValidatePowerfulOnly(configuration.PowerfulOnly, errors);
            ValidateOutput(configuration.Output, errors);
            ValidateExclusions(configuration.Exclusions, errors);
            return errors;
        }

        private static void ValidateQueue(
            QueueConfiguration queue,
            ICollection<string> errors)
        {
            if (queue == null)
            {
                errors.Add("Queue configuration is required.");
                return;
            }

            if (queue.Capacity < 1 || queue.Capacity > 65536)
            {
                errors.Add("Queue.Capacity must be between 1 and 65536.");
            }

            if (queue.WorkerCount < 1 || queue.WorkerCount > 8)
            {
                errors.Add("Queue.WorkerCount must be between 1 and 8.");
            }
        }

        private static void ValidateRetryDelays(
            int[] delays,
            ICollection<string> errors)
        {
            if (delays == null || delays.Length == 0)
            {
                errors.Add("RetryDelaysMilliseconds must not be empty.");
                return;
            }

            if (delays[0] != 0)
            {
                errors.Add("RetryDelaysMilliseconds must begin with 0.");
            }

            int previous = -1;
            foreach (int delay in delays)
            {
                if (delay < 0 || delay > 300000)
                {
                    errors.Add(
                        "Retry delays must be between 0 and 300000 milliseconds.");
                    break;
                }

                if (delay < previous)
                {
                    errors.Add("Retry delays must be nondecreasing.");
                    break;
                }

                previous = delay;
            }
        }

        private static void ValidatePowerfulOnly(
            PowerfulOnlyConfiguration powerfulOnly,
            ICollection<string> errors)
        {
            if (powerfulOnly == null)
            {
                errors.Add("PowerfulOnly configuration is required.");
                return;
            }

            if (powerfulOnly.PrivilegedUserRids == null ||
                powerfulOnly.PrivilegedGroupRids == null ||
                powerfulOnly.ExactSids == null ||
                powerfulOnly.AdditionalSids == null)
            {
                errors.Add("PowerfulOnly collections must not be null.");
                return;
            }

            ValidateSids(powerfulOnly.ExactSids, "PowerfulOnly.ExactSids", errors);
            ValidateSids(
                powerfulOnly.AdditionalSids,
                "PowerfulOnly.AdditionalSids",
                errors);
        }

        private static void ValidateOutput(
            OutputConfiguration output,
            ICollection<string> errors)
        {
            if (output == null ||
                output.OperationalEventLog == null ||
                output.SecurityEventLog == null ||
                output.Json == null)
            {
                errors.Add("Output configuration is incomplete.");
                return;
            }

            string mode = output.SecurityEventLog.Mode;
            if (!String.Equals(mode, "Off", StringComparison.OrdinalIgnoreCase) &&
                !String.Equals(
                    mode,
                    "SuspiciousOnly",
                    StringComparison.OrdinalIgnoreCase) &&
                !String.Equals(mode, "All", StringComparison.OrdinalIgnoreCase))
            {
                errors.Add(
                    "Output.SecurityEventLog.Mode must be Off, SuspiciousOnly, or All.");
            }

            if (output.Json.Enabled &&
                String.IsNullOrWhiteSpace(output.Json.Directory))
            {
                errors.Add(
                    "Output.Json.Directory is required when JSON output is enabled.");
            }
            else if (output.Json.Enabled)
            {
                try
                {
                    string configured = System.IO.Path.GetFullPath(
                        Environment.ExpandEnvironmentVariables(
                            output.Json.Directory));
                    string allowedRoot = System.IO.Path.GetFullPath(
                        System.IO.Path.Combine(
                            Environment.GetFolderPath(
                                Environment.SpecialFolder.CommonApplicationData),
                            "FindGT"));
                    if (!configured.StartsWith(
                        allowedRoot.TrimEnd('\\') + "\\",
                        StringComparison.OrdinalIgnoreCase))
                    {
                        errors.Add(
                            "Output.Json.Directory must be inside ProgramData\\FindGT.");
                    }
                }
                catch (ArgumentException exception)
                {
                    errors.Add(
                        "Output.Json.Directory is invalid: " + exception.Message);
                }
                catch (NotSupportedException exception)
                {
                    errors.Add(
                        "Output.Json.Directory is invalid: " + exception.Message);
                }
            }

            if (!output.OperationalEventLog.Enabled && !output.Json.Enabled)
            {
                errors.Add(
                    "At least OperationalEventLog or JSON output must be enabled.");
            }
        }

        private static void ValidateExclusions(
            ExclusionConfiguration exclusions,
            ICollection<string> errors)
        {
            if (exclusions == null ||
                exclusions.UserSids == null ||
                exclusions.AccountNames == null ||
                exclusions.Domains == null)
            {
                errors.Add("Exclusions collections must not be null.");
                return;
            }

            ValidateSids(exclusions.UserSids, "Exclusions.UserSids", errors);
        }

        private static void ValidateSids(
            IEnumerable<string> sids,
            string field,
            ICollection<string> errors)
        {
            foreach (string sid in sids)
            {
                if (String.IsNullOrWhiteSpace(sid))
                {
                    errors.Add(field + " contains an empty SID.");
                    continue;
                }

                try
                {
                    new SecurityIdentifier(sid);
                }
                catch (ArgumentException)
                {
                    errors.Add(field + " contains an invalid SID: " + sid + ".");
                }
            }
        }

        private static ConfigurationLoadResult Invalid(
            string path,
            string error)
        {
            return new ConfigurationLoadResult
            {
                Configuration = ServiceConfiguration.CreateDefault(),
                Path = path,
                IsValid = false,
                UsedDefaults = true,
                Error = error
            };
        }
    }
}
