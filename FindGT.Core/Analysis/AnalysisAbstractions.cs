using System;
using System.Collections.Generic;
using System.Threading;
using FindGT.Membership;

namespace FindGT.Core.Analysis
{
    public interface ISessionAnalyzer
    {
        SessionAnalysisResult AnalyzeSession(
            LUID logonId,
            SessionTriggerContext trigger,
            CancellationToken cancellationToken);

        IReadOnlyCollection<LogonSessionSnapshot> EnumerateSessions(
            CancellationToken cancellationToken);
    }

    internal interface ISessionDataSource
    {
        LogonSessionSnapshot GetSession(LUID logonId);
        IReadOnlyCollection<LogonSessionSnapshot> EnumerateSessions();
        IReadOnlyList<TokenGroupInfo> GetTokenGroups(LUID logonId);
    }

    internal interface IReferenceMembershipResolver
    {
        MembershipResult Resolve(LogonSessionSnapshot session);
    }
}
