using System;
using System.Collections.Generic;
using System.Security.Principal;

namespace FindGT
{
    public class NetlogonValidationSamInfo
    {
        public DateTime? LogonTime { get; set; }
        public DateTime? LogoffTime { get; set; }
        public DateTime? KickOffTime { get; set; }
        public DateTime? PasswordLastSet { get; set; }
        public DateTime? PasswordCanChange { get; set; }
        public DateTime? PasswordMustChange { get; set; }
        public string EffectiveName { get; set; }
        public string FullName { get; set; }
        public string LogonScript { get; set; }
        public string ProfilePath { get; set; }
        public string HomeDirectory { get; set; }
        public string HomeDirectoryDrive { get; set; }
        public ushort LogonCount { get; set; }
        public ushort BadPasswordCount { get; set; }
        public uint UserId { get; set; }
        public uint PrimaryGroupId { get; set; }
        public List<GroupMembership> GroupIds { get; set; } = new List<GroupMembership>();
        public uint UserFlags { get; set; }
        public byte[] UserSessionKey { get; set; } = new byte[16];
        public string LogonServer { get; set; }
        public string LogonDomainName { get; set; }
        public SecurityIdentifier LogonDomainId { get; set; }
        public List<int> ExpansionRoom { get; set; } = new List<int>(new int[10]);
        public uint SidCount { get; set; }
        public List<NetlogonSidAndAttributes> ExtraSids { get; set; } = new List<NetlogonSidAndAttributes>();
        public byte[] LmKey { get; set; } = new byte[8];
        public uint UserAccountControl { get; set; }
        public uint SubAuthStatus { get; set; }
        public DateTime? LastSuccessfulLogon { get; set; }
        public DateTime? LastFailedLogon { get; set; }
        public uint FailedILogonCount { get; set; }
        public uint Reserved4 { get; set; }
        public string DnsLogonDomainName { get; set; }
        public string Upn { get; set; }
        public List<string> ExpansionStrings { get; set; } = new List<string>(new string[10]);
    }

    public struct GroupMembership
    {
        public uint RelativeId { get; set; }
        public uint Attributes { get; set; }
    }

    public struct NetlogonSidAndAttributes
    {
        public SecurityIdentifier Sid { get; set; }
        public uint Attributes { get; set; }
    }
}
