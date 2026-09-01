using System;

namespace FindGT.Core.Analysis
{
    public static class RuntimeIdentity
    {
        public static Guid BootInstanceId
        {
            get { return BootInstanceIdProvider.Current; }
        }
    }
}
