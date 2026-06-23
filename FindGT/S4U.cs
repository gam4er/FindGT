using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
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
        /// The caller owns the token and must CloseHandle it. Throws on failure.
        /// </summary>
        public static IntPtr LogonUser(string upn, string realm, Action<string> log)
        {
            if (log == null) log = delegate { };
            if (string.IsNullOrWhiteSpace(upn)) throw new ArgumentException("upn is required");

            IntPtr lsaHandle = IntPtr.Zero;
            IntPtr s4uBuffer = IntPtr.Zero;
            IntPtr profileBuffer = IntPtr.Zero;
            Interop.LSA_STRING originName = default(Interop.LSA_STRING);
            Interop.LSA_STRING packageName = default(Interop.LSA_STRING);
            Interop.LSA_STRING processName = default(Interop.LSA_STRING);

            try
            {
                // 1. Register a trusted logon process (needs SeTcbPrivilege => SYSTEM).
                processName = NewLsaString("FindGT");
                ulong securityMode;
                uint status = Interop.LsaRegisterLogonProcess(ref processName, out lsaHandle, out securityMode);
                if (status != 0)
                    throw new Exception("LsaRegisterLogonProcess failed: NTSTATUS 0x" + status.ToString("x8") +
                                        " (" + Interop.LsaNtStatusToWinError(status) + ") — needs SYSTEM/SeTcbPrivilege.");

                // 2. Look up the Kerberos authentication package.
                packageName = NewLsaString("Kerberos");
                uint authPackage;
                status = Interop.LsaLookupAuthenticationPackage(lsaHandle, ref packageName, out authPackage);
                if (status != 0)
                    throw new Exception("LsaLookupAuthenticationPackage(Kerberos) failed: NTSTATUS 0x" + status.ToString("x8"));

                // 3. Build the KERB_S4U_LOGON buffer (struct + contiguous UPN/realm strings).
                int structSize = Marshal.SizeOf(typeof(KERB_S4U_LOGON));
                byte[] upnBytes = Encoding.Unicode.GetBytes(upn);
                byte[] realmBytes = Encoding.Unicode.GetBytes(realm ?? string.Empty);
                int bufferLen = structSize + upnBytes.Length + realmBytes.Length;
                s4uBuffer = Marshal.AllocHGlobal(bufferLen);
                long basePtr = s4uBuffer.ToInt64();

                KERB_S4U_LOGON s4u = new KERB_S4U_LOGON
                {
                    MessageType = (uint)KERB_LOGON_SUBMIT_TYPE.KerbS4ULogon,
                    Flags = 0,
                    ClientUpn = new Interop.UNICODE_STRING
                    {
                        Length = (ushort)upnBytes.Length,
                        MaximumLength = (ushort)upnBytes.Length,
                        Buffer = new IntPtr(basePtr + structSize)
                    },
                    ClientRealm = new Interop.UNICODE_STRING
                    {
                        Length = (ushort)realmBytes.Length,
                        MaximumLength = (ushort)realmBytes.Length,
                        Buffer = new IntPtr(basePtr + structSize + upnBytes.Length)
                    }
                };
                Marshal.StructureToPtr(s4u, s4uBuffer, false);
                if (upnBytes.Length > 0) Marshal.Copy(upnBytes, 0, s4u.ClientUpn.Buffer, upnBytes.Length);
                if (realmBytes.Length > 0) Marshal.Copy(realmBytes, 0, s4u.ClientRealm.Buffer, realmBytes.Length);

                // 4. LsaLogonUser with the S4U buffer.
                originName = NewLsaString("FindGT");
                Interop.TOKEN_SOURCE tokenSource = new Interop.TOKEN_SOURCE
                {
                    SourceName = new byte[] { (byte)'F', (byte)'i', (byte)'n', (byte)'d', (byte)'G', (byte)'T', 0, 0 }
                };
                Interop.AllocateLocallyUniqueId(out tokenSource.SourceIdentifier);

                IntPtr token;
                uint profileLength;
                LUID logonId;
                Interop.QUOTA_LIMITS quotas;
                uint subStatus;

                status = Interop.LsaLogonUser(
                    lsaHandle,
                    ref originName,
                    Interop.SECURITY_LOGON_TYPE.Network,
                    authPackage,
                    s4uBuffer,
                    (uint)bufferLen,
                    IntPtr.Zero,
                    ref tokenSource,
                    out profileBuffer,
                    out profileLength,
                    out logonId,
                    out token,
                    out quotas,
                    out subStatus);

                if (status != 0)
                    throw new Exception("LsaLogonUser(S4U) failed: NTSTATUS 0x" + status.ToString("x8") +
                                        " SubStatus 0x" + subStatus.ToString("x8") +
                                        " (Win32 " + Interop.LsaNtStatusToWinError(status) + ").");

                log("[+] S4U2Self logon OK for '" + upn + "' (LogonId 0x" + logonId.HighPart.ToString("x") +
                    logonId.LowPart.ToString("x8") + ").");
                return token;
            }
            finally
            {
                if (profileBuffer != IntPtr.Zero) Interop.LsaFreeReturnBuffer(profileBuffer);
                if (s4uBuffer != IntPtr.Zero) Marshal.FreeHGlobal(s4uBuffer);
                FreeLsaString(processName);
                FreeLsaString(packageName);
                FreeLsaString(originName);
                if (lsaHandle != IntPtr.Zero) Interop.LsaDeregisterLogonProcess(lsaHandle);
            }
        }

        /// <summary>
        /// Returns all group SIDs from an S4U2Self token for the given user.
        /// </summary>
        public static List<string> GetGroupSids(string upn, string realm, Action<string> log)
        {
            IntPtr token = IntPtr.Zero;
            try
            {
                token = LogonUser(upn, realm, log);
                return Helpers.GetTokenGroups(token);
            }
            finally
            {
                if (token != IntPtr.Zero) Interop.CloseHandle(token);
            }
        }

        /// <summary>
        /// Returns only the domain group SIDs (S-1-5-21-...) — the set relevant to forged-membership detection.
        /// </summary>
        public static HashSet<string> GetDomainGroupSids(string upn, string realm, Action<string> log)
        {
            return new HashSet<string>(
                GetGroupSids(upn, realm, log).Where(s => s != null && s.StartsWith("S-1-5-21-")),
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
            catch (Exception ex)
            {
                Console.WriteLine("[!] S4U2Self test FAILED: " + ex.Message);
            }
        }

        private static string TryResolveSid(string sid)
        {
            try
            {
                var sd = new System.Security.Principal.SecurityIdentifier(sid);
                var acct = (System.Security.Principal.NTAccount)sd.Translate(typeof(System.Security.Principal.NTAccount));
                return acct.Value;
            }
            catch
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
