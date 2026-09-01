using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace FindGT.Core.Analysis
{
    internal static class LocalMachineSidResolver
    {
        private const uint PolicyViewLocalInformation = 0x00000001;

        internal static string GetAccountDomainSid()
        {
            Interop.LSA_OBJECT_ATTRIBUTES attributes =
                new Interop.LSA_OBJECT_ATTRIBUTES
                {
                    Length = (uint)Marshal.SizeOf(
                        typeof(Interop.LSA_OBJECT_ATTRIBUTES))
                };

            IntPtr rawPolicy;
            uint status = Interop.LsaOpenPolicy(
                IntPtr.Zero,
                ref attributes,
                PolicyViewLocalInformation,
                out rawPolicy);
            if (status != 0)
            {
                if (rawPolicy != IntPtr.Zero)
                {
                    Interop.LsaClose(rawPolicy);
                }

                throw NativeCallException.FromNtStatus(
                    "LsaOpenPolicy",
                    status,
                    null,
                    "PolicyAccountDomainInformation");
            }

            using (SafeLsaPolicyHandle policy =
                new SafeLsaPolicyHandle(rawPolicy))
            {
                IntPtr rawInformation;
                status = Interop.LsaQueryInformationPolicy(
                    policy.DangerousGetHandle(),
                    Interop.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation,
                    out rawInformation);

                if (status != 0)
                {
                    if (rawInformation != IntPtr.Zero)
                    {
                        Interop.LsaFreeMemory(rawInformation);
                    }

                    throw NativeCallException.FromNtStatus(
                        "LsaQueryInformationPolicy",
                        status,
                        null,
                        "PolicyAccountDomainInformation");
                }

                using (SafeLsaMemory information =
                    new SafeLsaMemory(rawInformation))
                {
                    Interop.POLICY_ACCOUNT_DOMAIN_INFO domain =
                        (Interop.POLICY_ACCOUNT_DOMAIN_INFO)Marshal.PtrToStructure(
                            information.DangerousGetHandle(),
                            typeof(Interop.POLICY_ACCOUNT_DOMAIN_INFO));
                    if (domain.DomainSid == IntPtr.Zero)
                    {
                        throw new InvalidOperationException(
                            "The local account-domain SID is unavailable.");
                    }

                    return new SecurityIdentifier(domain.DomainSid).Value;
                }
            }
        }
    }
}
