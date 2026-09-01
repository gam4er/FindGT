using System;
using System.Collections.Generic;

namespace FindGT.Core.Analysis
{
    public sealed class PowerfulOnlyOptions
    {
        public PowerfulOnlyOptions()
        {
            PrivilegedUserRids = new HashSet<uint> { 500 };
            PrivilegedGroupRids = new HashSet<uint> { 512, 518, 519 };
            ExactSids = new HashSet<string>(
                new[] { "S-1-5-32-544" },
                StringComparer.OrdinalIgnoreCase);
            AdditionalSids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }

        public bool Enabled { get; set; }
        public ISet<uint> PrivilegedUserRids { get; private set; }
        public ISet<uint> PrivilegedGroupRids { get; private set; }
        public ISet<string> ExactSids { get; private set; }
        public ISet<string> AdditionalSids { get; private set; }
    }

    public sealed class AnalysisOptions
    {
        public AnalysisOptions()
        {
            EnabledLogonTypes = new HashSet<uint> { 3, 10 };
            ExcludedUserSids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            ExcludedAccountNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            ExcludedDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            PowerfulOnly = new PowerfulOnlyOptions();
        }

        public ISet<uint> EnabledLogonTypes { get; private set; }
        public ISet<string> ExcludedUserSids { get; private set; }
        public ISet<string> ExcludedAccountNames { get; private set; }
        public ISet<string> ExcludedDomains { get; private set; }
        public PowerfulOnlyOptions PowerfulOnly { get; private set; }
        public string LocalMachineSid { get; set; }

        public static AnalysisOptions ForCli()
        {
            AnalysisOptions options = new AnalysisOptions();
            options.EnabledLogonTypes.Clear();
            foreach (uint logonType in new uint[] { 2, 3, 4, 5, 8, 9, 10, 11, 12, 13 })
            {
                options.EnabledLogonTypes.Add(logonType);
            }

            return options;
        }
    }
}
