using System;

namespace FindGT.Membership
{
    /// <summary>
    /// Primary provider: authoritative membership via Kerberos S4U2Self (see <see cref="FindGT.S4U"/>).
    /// Tries the UPN form first, then falls back to DOMAIN\\user.
    /// </summary>
    public class S4UMembershipProvider : IMembershipProvider
    {
        public string Name { get { return "S4U2Self"; } }

        public MembershipResult GetExpectedGroups(MembershipQuery q, Action<string> log)
        {
            var result = new MembershipResult { Source = Name };

            if (q == null || (string.IsNullOrEmpty(q.Upn) && string.IsNullOrEmpty(q.Nt4Name)))
            {
                result.Error = "no UPN/NT4 name available";
                return result;
            }

            try
            {
                result.DomainGroupSids = S4U.GetDomainGroupSids(q.Upn, string.Empty, log);
                result.Success = true;
                return result;
            }
            catch (Exception exUpn)
            {
                if (!string.IsNullOrEmpty(q.Nt4Name))
                {
                    try
                    {
                        result.DomainGroupSids = S4U.GetDomainGroupSids(q.Nt4Name, q.DnsDomain, log);
                        result.Success = true;
                        return result;
                    }
                    catch (Exception exNt4)
                    {
                        result.Error = "UPN: " + exUpn.Message + " | NT4: " + exNt4.Message;
                        return result;
                    }
                }
                result.Error = exUpn.Message;
                return result;
            }
        }
    }
}
