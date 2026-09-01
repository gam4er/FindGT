using System;
using System.Collections.Generic;
using System.Security.Principal;
using FindGT.Core.Analysis;

namespace FindGT.Core.Rules
{
    public static class PowerfulSessionClassifier
    {
        public static PowerfulSessionClassification Classify(
            string userSid,
            IEnumerable<TokenGroupInfo> tokenGroups,
            PowerfulOnlyOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            uint userRid;
            if (!TryGetDomainRid(userSid, out userRid))
            {
                return new PowerfulSessionClassification
                {
                    IsPowerful = null,
                    MatchReason = "UserSidCouldNotBeClassified"
                };
            }

            if (options.PrivilegedUserRids.Contains(userRid))
            {
                return Match("UserRid:" + userRid);
            }

            if (options.AdditionalSids.Contains(userSid))
            {
                return Match("AdditionalUserSid:" + userSid);
            }

            if (tokenGroups == null)
            {
                return new PowerfulSessionClassification
                {
                    IsPowerful = null,
                    MatchReason = "TokenGroupsUnavailable"
                };
            }

            foreach (TokenGroupInfo group in tokenGroups)
            {
                if (group == null || String.IsNullOrWhiteSpace(group.Sid))
                {
                    return new PowerfulSessionClassification
                    {
                        IsPowerful = null,
                        MatchReason = "MalformedTokenGroupSid"
                    };
                }

                if (options.ExactSids.Contains(group.Sid))
                {
                    return Match("ExactSid:" + group.Sid);
                }

                if (options.AdditionalSids.Contains(group.Sid))
                {
                    return Match("AdditionalSid:" + group.Sid);
                }

                uint groupRid;
                if (TryGetDomainRid(group.Sid, out groupRid) &&
                    options.PrivilegedGroupRids.Contains(groupRid))
                {
                    return Match("GroupRid:" + groupRid);
                }
            }

            return new PowerfulSessionClassification
            {
                IsPowerful = false,
                MatchReason = "NoPrivilegedSidMatched"
            };
        }

        internal static bool TryGetRid(string sidValue, out uint rid)
        {
            rid = 0;
            if (String.IsNullOrWhiteSpace(sidValue))
            {
                return false;
            }

            try
            {
                SecurityIdentifier sid = new SecurityIdentifier(sidValue);
                byte[] binary = new byte[sid.BinaryLength];
                sid.GetBinaryForm(binary, 0);
                int subAuthorityCount = binary[1];
                if (subAuthorityCount == 0 ||
                    binary.Length != 8 + (subAuthorityCount * sizeof(uint)))
                {
                    return false;
                }

                rid = BitConverter.ToUInt32(
                    binary,
                    8 + ((subAuthorityCount - 1) * sizeof(uint)));
                return true;
            }
            catch (ArgumentException)
            {
                return false;
            }
        }

        private static bool TryGetDomainRid(string sidValue, out uint rid)
        {
            rid = 0;
            if (!TokenInspector.IsDomainSid(sidValue))
            {
                return false;
            }

            return TryGetRid(sidValue, out rid);
        }

        private static PowerfulSessionClassification Match(string reason)
        {
            return new PowerfulSessionClassification
            {
                IsPowerful = true,
                MatchReason = reason
            };
        }
    }
}
