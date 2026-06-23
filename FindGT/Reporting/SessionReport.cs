using System.Collections.Generic;
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

        /// <summary>True if any suspicious (in-session-not-in-reference) rows exist.</summary>
        public bool HasSuspicious
        {
            get
            {
                foreach (var r in Rows)
                    if (r.Kind == DiffKind.InSessionNotInReference)
                        return true;
                return false;
            }
        }
    }
}
