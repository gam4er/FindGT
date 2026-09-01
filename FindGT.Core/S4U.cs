using System;
using System.ComponentModel;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace FindGT
{
    /// <summary>
    /// Option A — Kerberos S4U2Self via the LSA logon API (KERB_S4U_LOGON).
    ///
    /// We ask LSA to log on a target domain user *without their password* using a Service-for-User
    /// (S4U2Self) request. LSA, acting as our machine account, asks the KDC for a ticket-to-self
    /// impersonating that user; the KDC builds a FRESH, authoritative PAC from current AD state.
    /// The resulting token therefore carries the user's REAL group membership — independent of any
    /// forged (golden) ticket present in the user's own logon session.
    ///
    /// Requires SYSTEM (SeTcbPrivilege) to register a trusted logon process and obtain a token.
    /// </summary>
    public static class S4U
    {
        internal sealed class MembershipSnapshot
        {
            internal string UserSid;
            internal List<string> GroupSids;
        }

        private enum KERB_LOGON_SUBMIT_TYPE
        {
            KerbInteractiveLogon = 2,
            KerbSmartCardLogon = 6,
            KerbWorkstationUnlockLogon = 7,
            KerbSmartCardUnlockLogon = 8,
            KerbProxyLogon = 9,
            KerbTicketLogon = 10,
            KerbTicketUnlockLogon = 11,
            KerbS4ULogon = 12,
            KerbCertificateLogon = 13,
            KerbCertificateS4ULogon = 14,
            KerbCertificateUnlockLogon = 15
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KERB_S4U_LOGON
        {
            public uint MessageType;            // KERB_LOGON_SUBMIT_TYPE
            public uint Flags;
            public Interop.UNICODE_STRING ClientUpn;
            public Interop.UNICODE_STRING ClientRealm;
        }

        /// <summary>
        /// Performs an S4U2Self logon for the given user and returns the resulting token.
        /// </summary>
        internal static SafeKernelHandle LogonUser(string upn, string realm, Action<string> log)
        {
            if (log == null) log = delegate { };
            if (string.IsNullOrWhiteSpace(upn))
                throw new ArgumentException("UPN is required.", "upn");

            Interop.LSA_STRING originName = default(Interop.LSA_STRING);
            Interop.LSA_STRING packageName = default(Interop.LSA_STRING);
            Interop.LSA_STRING processName = default(Interop.LSA_STRING);

            try
            {
                processName = NewLsaString("FindGT");
                ulong securityMode;
                IntPtr rawLsaHandle;
                uint status = Interop.LsaRegisterLogonProcess(
                    ref processName,
                    out rawLsaHandle,
                    out securityMode);

                if (status != 0)
                {
                    if (rawLsaHandle != IntPtr.Zero)
                    {
                        Interop.LsaDeregisterLogonProcess(rawLsaHandle);
                    }

                    throw NativeCallException.FromNtStatus(
                        "LsaRegisterLogonProcess",
                        status,
                        null,
                        "The process must run as LocalSystem with SeTcbPrivilege.");
                }

                using (SafeLsaLogonProcessHandle lsaHandle =
                    new SafeLsaLogonProcessHandle(rawLsaHandle))
                {
                    packageName = NewLsaString("Kerberos");
                    uint authenticationPackage;
                    status = Interop.LsaLookupAuthenticationPackage(
                        lsaHandle.DangerousGetHandle(),
                        ref packageName,
                        out authenticationPackage);

                    if (status != 0)
                    {
                        throw NativeCallException.FromNtStatus(
                            "LsaLookupAuthenticationPackage",
                            status,
                            null,
                            "Kerberos");
                    }

                    int structureSize = Marshal.SizeOf(typeof(KERB_S4U_LOGON));
                    byte[] upnBytes = Encoding.Unicode.GetBytes(upn);
                    byte[] realmBytes = Encoding.Unicode.GetBytes(realm ?? String.Empty);
                    if (upnBytes.Length > UInt16.MaxValue ||
                        realmBytes.Length > UInt16.MaxValue)
                    {
                        throw new ArgumentOutOfRangeException(
                            "upn",
                            "The UPN or realm is too long for KERB_S4U_LOGON.");
                    }

                    int bufferLength = checked(
                        structureSize + upnBytes.Length + realmBytes.Length);
                    using (SafeHGlobalBuffer s4uBuffer =
                        SafeHGlobalBuffer.Allocate(bufferLength))
                    {
                        long basePointer = s4uBuffer.DangerousGetHandle().ToInt64();
                        KERB_S4U_LOGON s4u = new KERB_S4U_LOGON
                        {
                            MessageType = (uint)KERB_LOGON_SUBMIT_TYPE.KerbS4ULogon,
                            Flags = 0,
                            ClientUpn = new Interop.UNICODE_STRING
                            {
                                Length = (ushort)upnBytes.Length,
                                MaximumLength = (ushort)upnBytes.Length,
                                Buffer = new IntPtr(checked(basePointer + structureSize))
                            },
                            ClientRealm = new Interop.UNICODE_STRING
                            {
                                Length = (ushort)realmBytes.Length,
                                MaximumLength = (ushort)realmBytes.Length,
                                Buffer = new IntPtr(checked(
                                    basePointer + structureSize + upnBytes.Length))
                            }
                        };

                        Marshal.StructureToPtr(
                            s4u,
                            s4uBuffer.DangerousGetHandle(),
                            false);
                        if (upnBytes.Length != 0)
                        {
                            Marshal.Copy(
                                upnBytes,
                                0,
                                s4u.ClientUpn.Buffer,
                                upnBytes.Length);
                        }

                        if (realmBytes.Length != 0)
                        {
                            Marshal.Copy(
                                realmBytes,
                                0,
                                s4u.ClientRealm.Buffer,
                                realmBytes.Length);
                        }

                        originName = NewLsaString("FindGT");
                        Interop.TOKEN_SOURCE tokenSource = new Interop.TOKEN_SOURCE
                        {
                            SourceName = new byte[]
                            {
                                (byte)'F', (byte)'i', (byte)'n', (byte)'d',
                                (byte)'G', (byte)'T', 0, 0
                            }
                        };

                        if (!Interop.AllocateLocallyUniqueId(
                            out tokenSource.SourceIdentifier))
                        {
                            throw new Win32Exception(
                                Marshal.GetLastWin32Error(),
                                "AllocateLocallyUniqueId failed.");
                        }

                        IntPtr rawProfileBuffer;
                        IntPtr rawToken;
                        uint profileLength;
                        LUID logonId;
                        Interop.QUOTA_LIMITS quotas;
                        uint subStatus;

                        status = Interop.LsaLogonUser(
                            lsaHandle.DangerousGetHandle(),
                            ref originName,
                            Interop.SECURITY_LOGON_TYPE.Network,
                            authenticationPackage,
                            s4uBuffer.DangerousGetHandle(),
                            (uint)bufferLength,
                            IntPtr.Zero,
                            ref tokenSource,
                            out rawProfileBuffer,
                            out profileLength,
                            out logonId,
                            out rawToken,
                            out quotas,
                            out subStatus);

                        using (SafeLsaReturnBuffer profileBuffer =
                            new SafeLsaReturnBuffer(rawProfileBuffer))
                        {
                            SafeKernelHandle token = new SafeKernelHandle(rawToken);
                            if (status != 0)
                            {
                                token.Dispose();
                                throw NativeCallException.FromNtStatus(
                                    "LsaLogonUser(S4U2Self)",
                                    status,
                                    null,
                                    "SubStatus 0x" + subStatus.ToString("X8"));
                            }

                            log(
                                "[+] S4U2Self logon OK for '" + upn +
                                "' (LogonId " + logonId + ").");
                            return token;
                        }
                    }
                }
            }
            finally
            {
                FreeLsaString(processName);
                FreeLsaString(packageName);
                FreeLsaString(originName);
            }
        }

        /// <summary>
        /// Returns all group SIDs from an S4U2Self token for the given user.
        /// </summary>
        public static List<string> GetGroupSids(string upn, string realm, Action<string> log)
        {
            return GetMembership(upn, realm, log).GroupSids;
        }

        internal static MembershipSnapshot GetMembership(
            string upn,
            string realm,
            Action<string> log)
        {
            using (SafeKernelHandle token = LogonUser(upn, realm, log))
            {
                return new MembershipSnapshot
                {
                    UserSid = TokenInspector.GetTokenUser(
                        token.DangerousGetHandle()).Value,
                    GroupSids = TokenInspector.GetTokenGroups(
                        token.DangerousGetHandle())
                };
            }
        }

        /// <summary>
        /// Returns only the domain group SIDs (S-1-5-21-...) — the set relevant to forged-membership detection.
        /// </summary>
        public static HashSet<string> GetDomainGroupSids(string upn, string realm, Action<string> log)
        {
            return new HashSet<string>(
                GetMembership(upn, realm, log).GroupSids.Where(
                    s => s != null && s.StartsWith("S-1-5-21-")),
                StringComparer.OrdinalIgnoreCase);
        }

        public static void Test(string upn, string realm)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(upn))
                {
                    Console.WriteLine("[!] Usage: FindGT.exe --test-s4u <user@realm | DOMAIN\\user> [realm]");
                    return;
                }

                Console.WriteLine("[*] S4U2Self for: " + upn + (string.IsNullOrEmpty(realm) ? "" : "  realm=" + realm));
                List<string> sids = GetGroupSids(upn, realm, Console.WriteLine);

                Console.WriteLine();
                Console.WriteLine("[*] Token contains " + sids.Count + " group SIDs:");
                foreach (string sid in sids)
                {
                    string name = TryResolveSid(sid);
                    bool domain = sid.StartsWith("S-1-5-21-");
                    Console.WriteLine("    " + (domain ? "[D] " : "    ") + sid + (name != null ? "  (" + name + ")" : ""));
                }

                int domainCount = sids.Count(s => s.StartsWith("S-1-5-21-"));
                Console.WriteLine();
                Console.WriteLine("[+] Authoritative domain groups (S-1-5-21-*): " + domainCount);
            }
            catch (NativeCallException ex)
            {
                PrintTestFailure(ex);
            }
            catch (Win32Exception ex)
            {
                PrintTestFailure(ex);
            }
            catch (ArgumentException ex)
            {
                PrintTestFailure(ex);
            }
            catch (InvalidOperationException ex)
            {
                PrintTestFailure(ex);
            }
        }

        private static void PrintTestFailure(Exception exception)
        {
            Console.WriteLine(
                "[!] S4U2Self test FAILED: " + exception.Message);
        }

        private static string TryResolveSid(string sid)
        {
            try
            {
                var sd = new System.Security.Principal.SecurityIdentifier(sid);
                var acct = (System.Security.Principal.NTAccount)sd.Translate(typeof(System.Security.Principal.NTAccount));
                return acct.Value;
            }
            catch (IdentityNotMappedException)
            {
                return null;
            }
            catch (ArgumentException)
            {
                return null;
            }
        }

        private static Interop.LSA_STRING NewLsaString(string s)
        {
            return new Interop.LSA_STRING
            {
                Buffer = Marshal.StringToHGlobalAnsi(s),
                Length = (ushort)s.Length,
                MaximumLength = (ushort)(s.Length + 1)
            };
        }

        private static void FreeLsaString(Interop.LSA_STRING s)
        {
            if (s.Buffer != IntPtr.Zero) Marshal.FreeHGlobal(s.Buffer);
        }
    }
}
