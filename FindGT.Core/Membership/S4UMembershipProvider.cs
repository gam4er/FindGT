using System;
using System.ComponentModel;

namespace FindGT.Membership
{
    public sealed class S4UMembershipProvider : IMembershipProvider
    {
        public string Name
        {
            get { return "S4U2Self"; }
        }

        public MembershipResult GetExpectedGroups(MembershipQuery query, Action<string> log)
        {
            MembershipResult result = new MembershipResult { Source = Name };
            if (query == null ||
                (String.IsNullOrWhiteSpace(query.Upn) &&
                 String.IsNullOrWhiteSpace(query.Nt4Name)))
            {
                result.Error = "No UPN or NT4 account name is available.";
                return result;
            }

            string upnError = null;
            if (!String.IsNullOrWhiteSpace(query.Upn))
            {
                if (TryResolveGroups(
                    query.Upn,
                    String.Empty,
                    log,
                    result,
                    out upnError))
                {
                    return result;
                }
            }

            string nt4Error = null;
            if (!String.IsNullOrWhiteSpace(query.Nt4Name))
            {
                if (TryResolveGroups(
                    query.Nt4Name,
                    query.DnsDomain,
                    log,
                    result,
                    out nt4Error))
                {
                    return result;
                }
            }

            result.Error =
                (!String.IsNullOrWhiteSpace(upnError) ? "UPN: " + upnError : String.Empty) +
                (!String.IsNullOrWhiteSpace(upnError) &&
                 !String.IsNullOrWhiteSpace(nt4Error) ? " | " : String.Empty) +
                (!String.IsNullOrWhiteSpace(nt4Error) ? "NT4: " + nt4Error : String.Empty);
            return result;
        }

        private static bool TryResolveGroups(
            string accountName,
            string realm,
            Action<string> log,
            MembershipResult result,
            out string error)
        {
            try
            {
                S4U.MembershipSnapshot snapshot = S4U.GetMembership(
                    accountName,
                    realm,
                    log);
                result.DomainGroupSids = new System.Collections.Generic.HashSet<string>(
                    snapshot.GroupSids.FindAll(sid =>
                        sid != null &&
                        sid.StartsWith("S-1-5-21-", StringComparison.Ordinal)),
                    StringComparer.OrdinalIgnoreCase);
                result.AccountExists = true;
                result.ResolvedUserSid = snapshot.UserSid;
                int separator = accountName.LastIndexOf('\\');
                string resolvedName = separator >= 0
                    ? accountName.Substring(separator + 1)
                    : accountName;
                int at = resolvedName.IndexOf('@');
                result.ResolvedSamAccountName = at > 0
                    ? resolvedName.Substring(0, at)
                    : resolvedName;
                result.Success = true;
                error = null;
                return true;
            }
            catch (NativeCallException exception)
            {
                error = exception.Message;
            }
            catch (Win32Exception exception)
            {
                error = exception.Message;
            }
            catch (ArgumentException exception)
            {
                error = exception.Message;
            }
            catch (InvalidOperationException exception)
            {
                error = exception.Message;
            }

            return false;
        }
    }
}
