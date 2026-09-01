using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;

namespace FindGT.Cli
{
    internal static class SystemContext
    {
        internal static bool IsHighIntegrity()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        internal static bool TryImpersonateLocalSystem()
        {
            if (!IsHighIntegrity())
            {
                return false;
            }

            Process[] processes = Process.GetProcessesByName("winlogon");
            try
            {
                foreach (Process process in processes)
                {
                    IntPtr rawToken;
                    if (!Interop.OpenProcessToken(process.Handle, 0x0002, out rawToken))
                    {
                        continue;
                    }

                    using (SafeKernelHandle token = new SafeKernelHandle(rawToken))
                    {
                        IntPtr rawDuplicate = IntPtr.Zero;
                        if (!Interop.DuplicateToken(
                            token.DangerousGetHandle(),
                            2,
                            ref rawDuplicate))
                        {
                            continue;
                        }

                        using (SafeKernelHandle duplicate = new SafeKernelHandle(rawDuplicate))
                        {
                            if (!Interop.ImpersonateLoggedOnUser(
                                duplicate.DangerousGetHandle()))
                            {
                                continue;
                            }

                            if (IsLocalSystem())
                            {
                                return true;
                            }

                            Interop.RevertToSelf();
                        }
                    }
                }
            }
            catch (Win32Exception exception)
            {
                Console.Error.WriteLine(
                    "  [!] LocalSystem impersonation failed: " + exception.Message);
            }
            catch (InvalidOperationException exception)
            {
                Console.Error.WriteLine(
                    "  [!] LocalSystem impersonation failed: " + exception.Message);
            }
            finally
            {
                foreach (Process process in processes)
                {
                    process.Dispose();
                }
            }

            return false;
        }

        internal static bool IsLocalSystem()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                SecurityIdentifier currentSid = identity.User;
                return currentSid != null &&
                    currentSid.IsWellKnown(WellKnownSidType.LocalSystemSid);
            }
        }
    }
}
