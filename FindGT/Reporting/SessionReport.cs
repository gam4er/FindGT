using System.Collections.Generic;
using FindGT.Core;
using FindGT.Membership;

namespace FindGT.Reporting
{
    /// <summary>Per-session comparison result, ready for rendering.</summary>
    public class SessionReport
    {
        public string Luid;
        public string UserSid;
        public string UserName;
        public string AuthPackage;

        public string ReferenceSource;          // provider that produced the expected membership
        public bool ReferenceOk;
        public string ReferenceError;

        public int TokenDomainGroupCount;
        public int ReferenceDomainGroupCount;

        public List<DiffRow> Rows = new List<DiffRow>();
        public AnalysisVerdict Verdict;
        public AnalysisReason Reason;
        public List<string> RuleIds = new List<string>();

        /// <summary>True if any suspicious (in-session-not-in-reference) rows exist.</summary>
        public bool HasSuspicious
        {
            get
            {
                return Verdict == AnalysisVerdict.Suspicious;
            }
        }

        public bool IsUnknown
        {
            get
            {
                return Verdict == AnalysisVerdict.Unknown ||
                    Verdict == AnalysisVerdict.Error;
            }
        }

        public bool IsNotEvaluated
        {
            get { return Verdict == AnalysisVerdict.NotEvaluated; }
        }
    }
}
