using System.Collections.Generic;

namespace FindGT.Membership
{
    public enum DiffKind
    {
        Match,                      // present in both token and reference
        InSessionNotInReference,    // in the suspected session token but NOT authoritative -> suspicious
        InReferenceNotInSession     // authoritative but missing from the session token
    }

    public class DiffRow
    {
        public string Sid;
        public string Name;
        public DiffKind Kind;
        public bool IsUserSid;      // SID resolves to a user/computer account, not a group
        public string Comment;
    }

    /// <summary>
    /// Compares the suspected session token's domain groups against an authoritative reference set.
    /// Base direction: iterate token groups, flag those absent from the reference (possible forgery);
    /// then the reverse: reference groups missing from the token.
    /// </summary>
    public static class MembershipComparer
    {
        public static List<DiffRow> Compare(ISet<string> tokenGroups, ISet<string> referenceGroups, bool verbose)
        {
            if (tokenGroups == null)
                throw new System.ArgumentNullException("tokenGroups");
            if (referenceGroups == null)
                throw new System.ArgumentNullException("referenceGroups");

            var rows = new List<DiffRow>();

            foreach (var sid in tokenGroups)
            {
                if (referenceGroups.Contains(sid))
                {
                    if (verbose)
                        rows.Add(new DiffRow { Sid = sid, Kind = DiffKind.Match, Comment = "OK: есть в токене и в эталоне" });
                }
                else
                {
                    rows.Add(new DiffRow { Sid = sid, Kind = DiffKind.InSessionNotInReference, Comment = "есть в токене, нет в эталоне" });
                }
            }

            foreach (var sid in referenceGroups)
            {
                if (!tokenGroups.Contains(sid))
                {
                    rows.Add(new DiffRow { Sid = sid, Kind = DiffKind.InReferenceNotInSession, Comment = "есть в эталоне, нет в токене" });
                }
            }

            return rows;
        }

        /// <summary>Resolves names for all rows and flags user SIDs among the suspicious (in-session) rows.</summary>
        public static void Enrich(List<DiffRow> rows)
        {
            foreach (var r in rows)
            {
                string name;
                bool isUser;
                SidUtil.Classify(r.Sid, out name, out isUser);
                r.Name = name;

                if (r.Kind == DiffKind.InSessionNotInReference)
                {
                    r.IsUserSid = isUser;
                    if (isUser)
                        r.Comment = "SID ПОЛЬЗОВАТЕЛЯ в членстве, в эталоне отсутствует";
                }
            }
        }
    }
}
