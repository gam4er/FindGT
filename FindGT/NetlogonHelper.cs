using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace FindGT
{
    public static class NetlogonHelper
    {
        private const uint LOGON_EXTRA_SIDS = 0x20;
        private const string LogonProcessName = "FindGT";
        private const string AuthenticationPackage = "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0";
        private const string KerberosAuthenticationPackage = "Kerberos";

        private const uint STATUS_NOT_SUPPORTED = 0xC00000BB;
        private const uint STATUS_NO_S4U_PROT_SUPPORT = 0xC000040A;

        public static NetlogonValidationSamInfo GetValidationSamInfo(
            SecurityIdentifier userSid,
            string userName,
            string domainNetbios = null,
            string dnsDomainName = null,
            string domainController = null)
        {
            if (userSid == null)
            {
                throw new ArgumentNullException(nameof(userSid));
            }

            if (string.IsNullOrWhiteSpace(userName))
            {
                throw new ArgumentException("User name cannot be empty", nameof(userName));
            }

            string samAccountName = userName;
            string explicitDomain = domainNetbios;

            if (samAccountName.Contains("\\"))
            {
                string[] parts = samAccountName.Split(new[] { '\\' }, 2);
                if (parts.Length == 2)
                {
                    if (string.IsNullOrEmpty(explicitDomain))
                    {
                        explicitDomain = parts[0];
                    }
                    samAccountName = parts[1];
                }
            }
            else if (samAccountName.Contains("@"))
            {
                string[] parts = samAccountName.Split(new[] { '@' }, 2);
                if (parts.Length == 2 && string.IsNullOrEmpty(dnsDomainName))
                {
                    dnsDomainName = parts[1];
                }
                if (parts.Length == 2)
                {
                    samAccountName = parts[0];
                }
            }

            if (string.IsNullOrEmpty(explicitDomain))
            {
                try
                {
                    NTAccount account = (NTAccount)userSid.Translate(typeof(NTAccount));
                    string[] nameParts = account.Value.Split('\\');
                    if (nameParts.Length == 2)
                    {
                        explicitDomain = nameParts[0];
                    }
                }
                catch
                {
                    // ignore translation errors
                }
            }

            IntPtr logonProcessBuffer = IntPtr.Zero;
            IntPtr originNameBuffer = IntPtr.Zero;
            IntPtr packageNameBuffer = IntPtr.Zero;
            IntPtr logonBuffer = IntPtr.Zero;
            IntPtr profileBuffer = IntPtr.Zero;
            IntPtr tokenHandle = IntPtr.Zero;
            IntPtr lsaHandle = IntPtr.Zero;
            IntPtr kerberosPackageBuffer = IntPtr.Zero;

            try
            {
                Interop.LSA_STRING logonProcessName = CreateLsaString(LogonProcessName, out logonProcessBuffer);

                ulong securityMode;
                uint ntstatus = Interop.LsaRegisterLogonProcess(ref logonProcessName, out lsaHandle, out securityMode);
                if (ntstatus != 0)
                {
                    throw new Win32Exception((int)Interop.LsaNtStatusToWinError(ntstatus));
                }

                Interop.LSA_STRING originName = CreateLsaString(LogonProcessName, out originNameBuffer);
                Interop.LSA_STRING packageName = CreateLsaString(AuthenticationPackage, out packageNameBuffer);

                uint authenticationPackage;
                ntstatus = Interop.LsaLookupAuthenticationPackage(lsaHandle, ref packageName, out authenticationPackage);
                if (ntstatus != 0)
                {
                    throw new Win32Exception((int)Interop.LsaNtStatusToWinError(ntstatus));
                }

                string upnValue = BuildUpn(samAccountName, dnsDomainName, userName);
                byte[] userPrincipalNameBytes;
                Interop.UNICODE_STRING userPrincipalName = CreateUnicodeString(upnValue, out userPrincipalNameBytes);
                byte[] domainNameBytes;
                Interop.UNICODE_STRING domainName = CreateUnicodeString(explicitDomain, out domainNameBytes);

                Interop.MSV1_0_S4U_LOGON s4uLogon = new Interop.MSV1_0_S4U_LOGON
                {
                    MessageType = Interop.MSV1_0_LOGON_SUBMIT_TYPE.MsV1_0S4ULogon,
                    Flags = 0,
                    UserPrincipalName = userPrincipalName,
                    DomainName = domainName
                };

                uint totalLogonSize;
                logonBuffer = BuildMsvS4ULogonBuffer(ref s4uLogon, userPrincipalNameBytes, domainNameBytes, out totalLogonSize);

                Interop.TOKEN_SOURCE sourceContext = new Interop.TOKEN_SOURCE
                {
                    SourceName = new byte[8]
                };
                byte[] sourceNameBytes = Encoding.ASCII.GetBytes(LogonProcessName);
                Array.Copy(sourceNameBytes, sourceContext.SourceName, Math.Min(sourceNameBytes.Length, sourceContext.SourceName.Length));

                if (!Interop.AllocateLocallyUniqueId(out sourceContext.SourceIdentifier))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                }

                LUID logonId;
                Interop.QUOTA_LIMITS quotas;
                uint profileLength;
                uint subStatus;

                ntstatus = Interop.LsaLogonUser(
                    lsaHandle,
                    ref originName,
                    Interop.SECURITY_LOGON_TYPE.Network,
                    authenticationPackage,
                    logonBuffer,
                    totalLogonSize,
                    IntPtr.Zero,
                    ref sourceContext,
                    out profileBuffer,
                    out profileLength,
                    out logonId,
                    out tokenHandle,
                    out quotas,
                    out subStatus);

                if (ntstatus == STATUS_NOT_SUPPORTED || ntstatus == STATUS_NO_S4U_PROT_SUPPORT)
                {
                    if (logonBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(logonBuffer);
                        logonBuffer = IntPtr.Zero;
                    }

                    Interop.LSA_STRING kerberosPackageName = CreateLsaString(KerberosAuthenticationPackage, out kerberosPackageBuffer);

                    ntstatus = Interop.LsaLookupAuthenticationPackage(lsaHandle, ref kerberosPackageName, out authenticationPackage);
                    if (ntstatus != 0)
                    {
                        throw new Win32Exception((int)Interop.LsaNtStatusToWinError(ntstatus));
                    }

                    string kerberosRealmCandidate = !string.IsNullOrEmpty(dnsDomainName) ? dnsDomainName : explicitDomain;
                    string kerberosUpnValue = upnValue;
                    if (!string.IsNullOrEmpty(kerberosRealmCandidate) && (string.IsNullOrEmpty(kerberosUpnValue) || !kerberosUpnValue.Contains("@")))
                    {
                        kerberosUpnValue = string.Format("{0}@{1}", samAccountName, kerberosRealmCandidate);
                    }

                    string kerberosRealmValue = string.IsNullOrEmpty(kerberosRealmCandidate)
                        ? null
                        : kerberosRealmCandidate.ToUpperInvariant();

                    byte[] kerberosUpnBytes;
                    Interop.UNICODE_STRING kerberosUpn = CreateUnicodeString(kerberosUpnValue, out kerberosUpnBytes);
                    byte[] kerberosRealmBytes;
                    Interop.UNICODE_STRING kerberosRealm = CreateUnicodeString(kerberosRealmValue, out kerberosRealmBytes);

                    Interop.KERB_S4U_LOGON kerbLogon = new Interop.KERB_S4U_LOGON
                    {
                        MessageType = Interop.KERB_LOGON_SUBMIT_TYPE.KerbS4ULogon,
                        Flags = 0,
                        ClientUpn = kerberosUpn,
                        ClientRealm = kerberosRealm
                    };

                    logonBuffer = BuildKerbS4ULogonBuffer(ref kerbLogon, kerberosUpnBytes, kerberosRealmBytes, out totalLogonSize);

                    profileBuffer = IntPtr.Zero;
                    tokenHandle = IntPtr.Zero;
                    logonId = default;
                    quotas = default;
                    profileLength = 0;
                    subStatus = 0;

                    ntstatus = Interop.LsaLogonUser(
                        lsaHandle,
                        ref originName,
                        Interop.SECURITY_LOGON_TYPE.Network,
                        authenticationPackage,
                        logonBuffer,
                        totalLogonSize,
                        IntPtr.Zero,
                        ref sourceContext,
                        out profileBuffer,
                        out profileLength,
                        out logonId,
                        out tokenHandle,
                        out quotas,
                        out subStatus);
                }

                if (ntstatus != 0)
                {
                    throw new Win32Exception((int)Interop.LsaNtStatusToWinError(ntstatus));
                }

                NetlogonValidationSamInfo info = BuildValidationInfo(userSid, samAccountName, explicitDomain, dnsDomainName, domainController, tokenHandle);
                return info;
            }
            finally
            {
                if (tokenHandle != IntPtr.Zero)
                {
                    Interop.CloseHandle(tokenHandle);
                }

                if (profileBuffer != IntPtr.Zero)
                {
                    Interop.LsaFreeReturnBuffer(profileBuffer);
                }

                if (logonBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(logonBuffer);
                }

                if (packageNameBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(packageNameBuffer);
                }

                if (kerberosPackageBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(kerberosPackageBuffer);
                }

                if (originNameBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(originNameBuffer);
                }

                if (logonProcessBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(logonProcessBuffer);
                }

                if (lsaHandle != IntPtr.Zero)
                {
                    Interop.LsaDeregisterLogonProcess(lsaHandle);
                }
            }
        }

        private static NetlogonValidationSamInfo BuildValidationInfo(
            SecurityIdentifier userSid,
            string samAccountName,
            string domainNetbios,
            string dnsDomainName,
            string domainController,
            IntPtr tokenHandle)
        {
            SecurityIdentifier domainSid = userSid.AccountDomainSid ?? userSid;
            SecurityIdentifier primaryGroup = Helpers.GetTokenPrimaryGroup(tokenHandle);
            List<Helpers.TokenGroup> tokenGroups = Helpers.GetTokenGroupsWithAttributes(tokenHandle);

            NetlogonValidationSamInfo info = new NetlogonValidationSamInfo
            {
                EffectiveName = samAccountName,
                LogonDomainName = domainNetbios ?? string.Empty,
                LogonDomainId = domainSid,
                LogonServer = string.IsNullOrEmpty(domainController) ? Environment.MachineName : domainController,
                LogonTime = DateTime.UtcNow,
                DnsLogonDomainName = !string.IsNullOrEmpty(dnsDomainName) ? dnsDomainName : domainNetbios,
                Upn = BuildUpn(samAccountName, dnsDomainName, null),
                UserId = GetRid(userSid),
                PrimaryGroupId = GetRid(primaryGroup)
            };

            if (tokenGroups != null)
            {
                foreach (Helpers.TokenGroup group in tokenGroups)
                {
                    SecurityIdentifier groupDomainSid = group.Sid.AccountDomainSid;
                    if (domainSid != null && groupDomainSid != null && groupDomainSid.Equals(domainSid))
                    {
                        info.GroupIds.Add(new GroupMembership
                        {
                            RelativeId = GetRid(group.Sid),
                            Attributes = group.Attributes
                        });
                    }
                    else
                    {
                        info.ExtraSids.Add(new NetlogonSidAndAttributes
                        {
                            Sid = group.Sid,
                            Attributes = group.Attributes
                        });
                    }
                }
            }

            info.SidCount = (uint)info.ExtraSids.Count;
            if (info.ExtraSids.Count > 0)
            {
                info.UserFlags |= LOGON_EXTRA_SIDS;
            }

            return info;
        }

        private static IntPtr BuildMsvS4ULogonBuffer(
            ref Interop.MSV1_0_S4U_LOGON logon,
            byte[] userPrincipalNameBytes,
            byte[] domainNameBytes,
            out uint totalSize)
        {
            int structSize = Marshal.SizeOf(typeof(Interop.MSV1_0_S4U_LOGON));
            int userPrincipalNameLength = userPrincipalNameBytes != null ? userPrincipalNameBytes.Length : 0;
            int domainNameLength = domainNameBytes != null ? domainNameBytes.Length : 0;
            int totalLogonSize = checked(structSize + userPrincipalNameLength + domainNameLength);

            IntPtr buffer = Marshal.AllocHGlobal(totalLogonSize);
            IntPtr currentBuffer = IntPtr.Add(buffer, structSize);

            if (userPrincipalNameLength > 0)
            {
                logon.UserPrincipalName.Buffer = currentBuffer;
                Marshal.Copy(userPrincipalNameBytes, 0, currentBuffer, userPrincipalNameLength);
                currentBuffer = IntPtr.Add(currentBuffer, userPrincipalNameLength);
            }
            else
            {
                logon.UserPrincipalName.Buffer = IntPtr.Zero;
            }

            if (domainNameLength > 0)
            {
                logon.DomainName.Buffer = currentBuffer;
                Marshal.Copy(domainNameBytes, 0, currentBuffer, domainNameLength);
                currentBuffer = IntPtr.Add(currentBuffer, domainNameLength);
            }
            else
            {
                logon.DomainName.Buffer = IntPtr.Zero;
            }

            Marshal.StructureToPtr(logon, buffer, false);
            totalSize = (uint)totalLogonSize;
            return buffer;
        }

        private static IntPtr BuildKerbS4ULogonBuffer(
            ref Interop.KERB_S4U_LOGON logon,
            byte[] clientUpnBytes,
            byte[] clientRealmBytes,
            out uint totalSize)
        {
            int structSize = Marshal.SizeOf(typeof(Interop.KERB_S4U_LOGON));
            int clientUpnLength = clientUpnBytes != null ? clientUpnBytes.Length : 0;
            int clientRealmLength = clientRealmBytes != null ? clientRealmBytes.Length : 0;
            int totalLogonSize = checked(structSize + clientUpnLength + clientRealmLength);

            IntPtr buffer = Marshal.AllocHGlobal(totalLogonSize);
            IntPtr currentBuffer = IntPtr.Add(buffer, structSize);

            if (clientUpnLength > 0)
            {
                logon.ClientUpn.Buffer = currentBuffer;
                Marshal.Copy(clientUpnBytes, 0, currentBuffer, clientUpnLength);
                currentBuffer = IntPtr.Add(currentBuffer, clientUpnLength);
            }
            else
            {
                logon.ClientUpn.Buffer = IntPtr.Zero;
            }

            if (clientRealmLength > 0)
            {
                logon.ClientRealm.Buffer = currentBuffer;
                Marshal.Copy(clientRealmBytes, 0, currentBuffer, clientRealmLength);
            }
            else
            {
                logon.ClientRealm.Buffer = IntPtr.Zero;
            }

            Marshal.StructureToPtr(logon, buffer, false);
            totalSize = (uint)totalLogonSize;
            return buffer;
        }

        private static Interop.LSA_STRING CreateLsaString(string value, out IntPtr buffer)
        {
            if (string.IsNullOrEmpty(value))
            {
                buffer = IntPtr.Zero;
                return new Interop.LSA_STRING
                {
                    Length = 0,
                    MaximumLength = 0,
                    Buffer = IntPtr.Zero
                };
            }

            buffer = Marshal.StringToHGlobalAnsi(value);
            return new Interop.LSA_STRING
            {
                Length = (ushort)value.Length,
                MaximumLength = (ushort)(value.Length + 1),
                Buffer = buffer
            };
        }

        private static Interop.UNICODE_STRING CreateUnicodeString(string value, out byte[] buffer)
        {
            if (string.IsNullOrEmpty(value))
            {
                buffer = null;
                return new Interop.UNICODE_STRING
                {
                    Length = 0,
                    MaximumLength = 0,
                    Buffer = IntPtr.Zero
                };
            }

            buffer = Encoding.Unicode.GetBytes(value + "\0");
            return new Interop.UNICODE_STRING
            {
                Length = (ushort)(buffer.Length - 2),
                MaximumLength = (ushort)buffer.Length,
                Buffer = IntPtr.Zero
            };
        }

        private static uint GetRid(SecurityIdentifier sid)
        {
            if (sid == null)
            {
                return 0;
            }

            string[] parts = sid.Value.Split('-');
            if (parts.Length == 0)
            {
                return 0;
            }

            string last = parts[parts.Length - 1];
            if (uint.TryParse(last, out uint rid))
            {
                return rid;
            }

            return 0;
        }

        private static string BuildUpn(string samAccountName, string dnsDomainName, string originalUserName)
        {
            if (!string.IsNullOrEmpty(originalUserName) && originalUserName.Contains("@"))
            {
                return originalUserName;
            }

            if (!string.IsNullOrEmpty(samAccountName) && !string.IsNullOrEmpty(dnsDomainName))
            {
                return string.Format("{0}@{1}", samAccountName, dnsDomainName);
            }

            return samAccountName;
        }
    }
}
