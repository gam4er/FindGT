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
                uint logonSize;
                logonBuffer = CreateS4ULogonBuffer(upnValue, explicitDomain, out logonSize);

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
                    logonSize,
                    IntPtr.Zero,
                    ref sourceContext,
                    out profileBuffer,
                    out profileLength,
                    out logonId,
                    out tokenHandle,
                    out quotas,
                    out subStatus);

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

        private static IntPtr CreateS4ULogonBuffer(string userPrincipalName, string domainName, out uint bufferSize)
        {
            int structSize = Marshal.SizeOf(typeof(Interop.MSV1_0_S4U_LOGON));
            int upnLength = string.IsNullOrEmpty(userPrincipalName) ? 0 : Encoding.Unicode.GetByteCount(userPrincipalName);
            int domainLength = string.IsNullOrEmpty(domainName) ? 0 : Encoding.Unicode.GetByteCount(domainName);

            if (upnLength > ushort.MaxValue - sizeof(char))
            {
                throw new ArgumentOutOfRangeException(nameof(userPrincipalName), "User principal name is too long for UNICODE_STRING.");
            }

            if (domainLength > ushort.MaxValue - sizeof(char))
            {
                throw new ArgumentOutOfRangeException(nameof(domainName), "Domain name is too long for UNICODE_STRING.");
            }

            long totalSize = structSize;

            if (upnLength > 0)
            {
                totalSize = AlignUp(totalSize, IntPtr.Size);
                totalSize += upnLength + sizeof(char);
            }

            if (domainLength > 0)
            {
                totalSize = AlignUp(totalSize, IntPtr.Size);
                totalSize += domainLength + sizeof(char);
            }

            if (totalSize > int.MaxValue)
            {
                throw new InvalidOperationException("Calculated logon buffer size exceeds supported limits.");
            }

            IntPtr buffer = Marshal.AllocHGlobal((int)totalSize);
            IntPtr current = IntPtr.Add(buffer, structSize);

            Interop.UNICODE_STRING upn = new Interop.UNICODE_STRING();
            if (upnLength > 0)
            {
                current = AlignPointer(current, IntPtr.Size);
                upn.Length = (ushort)upnLength;
                upn.MaximumLength = (ushort)(upnLength + sizeof(char));
                upn.Buffer = current;
                WriteUnicodeStringToPointer(userPrincipalName, upn.Buffer);
                current = IntPtr.Add(current, upn.MaximumLength);
            }
            else
            {
                upn.Length = 0;
                upn.MaximumLength = 0;
                upn.Buffer = IntPtr.Zero;
            }

            Interop.UNICODE_STRING domain = new Interop.UNICODE_STRING();
            if (domainLength > 0)
            {
                current = AlignPointer(current, IntPtr.Size);
                domain.Length = (ushort)domainLength;
                domain.MaximumLength = (ushort)(domainLength + sizeof(char));
                domain.Buffer = current;
                WriteUnicodeStringToPointer(domainName, domain.Buffer);
                current = IntPtr.Add(current, domain.MaximumLength);
            }
            else
            {
                domain.Length = 0;
                domain.MaximumLength = 0;
                domain.Buffer = IntPtr.Zero;
            }

            Interop.MSV1_0_S4U_LOGON logon = new Interop.MSV1_0_S4U_LOGON
            {
                MessageType = Interop.MSV1_0_LOGON_SUBMIT_TYPE.MsV1_0S4ULogon,
                Flags = 0,
                UserPrincipalName = upn,
                DomainName = domain
            };

            Marshal.StructureToPtr(logon, buffer, false);

            bufferSize = (uint)totalSize;
            return buffer;
        }

        private static void WriteUnicodeStringToPointer(string value, IntPtr buffer)
        {
            if (buffer == IntPtr.Zero || string.IsNullOrEmpty(value))
            {
                return;
            }

            byte[] data = Encoding.Unicode.GetBytes(value);
            Marshal.Copy(data, 0, buffer, data.Length);
            Marshal.WriteInt16(buffer, data.Length, 0);
        }

        private static long AlignUp(long value, int alignment)
        {
            long mask = alignment - 1;
            return (value + mask) & ~mask;
        }

        private static IntPtr AlignPointer(IntPtr pointer, int alignment)
        {
            long aligned = AlignUp(pointer.ToInt64(), alignment);
            return new IntPtr(aligned);
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
