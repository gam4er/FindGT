using System;
using System.Collections.Generic;
using System.Linq;

namespace FindGT.Core.Analysis
{
    internal sealed class NativeSessionDataSource : ISessionDataSource
    {
        private readonly Action<string> _errorLog;

        internal NativeSessionDataSource(Action<string> errorLog)
        {
            _errorLog = errorLog ?? delegate { };
        }

        public LogonSessionSnapshot GetSession(LUID logonId)
        {
            Find.FoundSession? session = Find.GetLogonSession(
                logonId,
                false,
                _errorLog);
            return session.HasValue ? Map(session.Value) : null;
        }

        public IReadOnlyCollection<LogonSessionSnapshot> EnumerateSessions()
        {
            return Find.LogonSessions(false, _errorLog)
                .Values
                .Select(Map)
                .ToList()
                .AsReadOnly();
        }

        public IReadOnlyList<TokenGroupInfo> GetTokenGroups(LUID logonId)
        {
            using (SafeKernelHandle token = Creds.NegotiateToken(
                logonId,
                null,
                false))
            {
                if (token.IsInvalid)
                {
                    throw new InvalidOperationException(
                        "Token negotiation returned an invalid handle.");
                }

                return TokenInspector.GetTokenGroupsWithAttributes(
                    token.DangerousGetHandle())
                    .Select(group => new TokenGroupInfo
                    {
                        Sid = group.Sid.Value,
                        Attributes = group.Attributes
                    })
                    .ToList()
                    .AsReadOnly();
            }
        }

        private static LogonSessionSnapshot Map(Find.FoundSession session)
        {
            return new LogonSessionSnapshot
            {
                LogonId = session.LogonId,
                UserName = session.UserName,
                AccountName = session.AccountName,
                CredentialUserName = session.CredentialUserName,
                LogonDomain = session.LogonDomain,
                DnsDomainName = session.DnsDomainName,
                Upn = session.Upn,
                UserSid = session.Sid,
                LogonType = (uint)session.LogonType,
                AuthenticationPackage = session.AuthenticationPackage,
                SessionId = session.Session,
                LogonTimeUtc = session.LogonTimeUtc,
                LogonServer = session.LogonServer,
                UserFlags = session.UserFlags
            };
        }
    }
}
