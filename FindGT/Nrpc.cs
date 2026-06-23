using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace FindGT
{
    /// <summary>
    /// MS-NRPC Netlogon secure-channel client. Establishes and verifies a secure channel
    /// against a domain controller using the machine account secret (NTOWFv1), via the
    /// netapi32 "I_Netlogon" RPC stubs. This is the authoritative-membership transport that
    /// bypasses the potentially-forged local Kerberos/LSA context.
    ///
    /// Phase 2a implements: DC locate -> NetrServerReqChallenge -> NetrServerAuthenticate3,
    /// with AES session-key derivation and server-credential verification.
    /// </summary>
    public class Nrpc
    {
        // NETLOGON_SECURE_CHANNEL_TYPE
        public const int WorkstationSecureChannel = 2;

        // Negotiate flags requesting AES + strong capabilities (bit 24 = NETLOGON_NEG_SUPPORTS_AES).
        public const uint NegotiateFlagsAes = 0x612FFFFF;
        public const uint NETLOGON_NEG_SUPPORTS_AES = 0x01000000;

        // DsGetDcName flags
        private const uint DS_RETURN_DNS_NAME = 0x40000000;
        private const uint DS_DIRECTORY_SERVICE_REQUIRED = 0x00000010;

        #region P/Invoke

        [DllImport("netapi32.dll", EntryPoint = "I_NetServerReqChallenge", CharSet = CharSet.Unicode)]
        private static extern int I_NetServerReqChallenge(
            string PrimaryName,
            string ComputerName,
            byte[] ClientChallenge,
            byte[] ServerChallenge);

        [DllImport("netapi32.dll", EntryPoint = "I_NetServerAuthenticate3", CharSet = CharSet.Unicode)]
        private static extern int I_NetServerAuthenticate3(
            string PrimaryName,
            string AccountName,
            int SecureChannelType,
            string ComputerName,
            byte[] ClientCredential,
            byte[] ServerCredential,
            ref uint NegotiateFlags,
            out uint AccountRid);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int DsGetDcName(
            string ComputerName,
            string DomainName,
            IntPtr DomainGuid,
            string SiteName,
            uint Flags,
            out IntPtr DomainControllerInfo);

        [DllImport("netapi32.dll")]
        private static extern int NetApiBufferFree(IntPtr Buffer);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DOMAIN_CONTROLLER_INFO
        {
            public string DomainControllerName;
            public string DomainControllerAddress;
            public uint DomainControllerAddressType;
            public Guid DomainGuid;
            public string DomainName;
            public string DnsForestName;
            public uint Flags;
            public string DcSiteName;
            public string ClientSiteName;
        }

        #endregion

        public class SecureChannel
        {
            public string DcName;
            public string ComputerName;
            public string AccountName;
            public byte[] SessionKey;
            public byte[] ClientCredential;
            public uint NegotiateFlags;
            public uint AccountRid;
            public bool AesNegotiated;
        }

        /// <summary>Locate a writable DC for the domain and return its UNC name (e.g. \\dc01.kl.local).</summary>
        public static string LocateDc(string domainName)
        {
            IntPtr buffer;
            int status = DsGetDcName(null, domainName, IntPtr.Zero, null,
                DS_RETURN_DNS_NAME | DS_DIRECTORY_SERVICE_REQUIRED, out buffer);
            if (status != 0)
                throw new System.ComponentModel.Win32Exception(status, "DsGetDcName failed (" + status + ").");
            try
            {
                DOMAIN_CONTROLLER_INFO info =
                    (DOMAIN_CONTROLLER_INFO)Marshal.PtrToStructure(buffer, typeof(DOMAIN_CONTROLLER_INFO));
                return info.DomainControllerName;
            }
            finally
            {
                NetApiBufferFree(buffer);
            }
        }

        /// <summary>
        /// Establish and verify a Netlogon secure channel using the machine NTOWFv1.
        /// Throws on any failure (RPC error or server-credential mismatch).
        /// </summary>
        public static SecureChannel Establish(byte[] ntHash, string dcName, string computerName, Action<string> log)
        {
            if (ntHash == null || ntHash.Length != 16)
                throw new ArgumentException("ntHash must be 16 bytes (NTOWFv1).");
            if (log == null) log = delegate { };
            if (string.IsNullOrEmpty(computerName))
                computerName = Environment.MachineName;
            string accountName = computerName + "$";

            byte[] clientChallenge = new byte[8];
            using (var rng = new RNGCryptoServiceProvider())
                rng.GetBytes(clientChallenge);
            byte[] serverChallenge = new byte[8];

            log("[*] DC               : " + dcName);
            log("[*] ComputerName     : " + computerName);
            log("[*] AccountName      : " + accountName);
            log("[*] ClientChallenge  : " + ToHex(clientChallenge));

            int rc = I_NetServerReqChallenge(dcName, computerName, clientChallenge, serverChallenge);
            if (rc != 0)
                throw new System.ComponentModel.Win32Exception(rc,
                    "I_NetServerReqChallenge failed (NTSTATUS 0x" + ((uint)rc).ToString("x8") + ").");
            log("[+] ReqChallenge OK. ServerChallenge: " + ToHex(serverChallenge));
            log("[*] ClientChallenge after ReqChallenge: " + ToHex(clientChallenge));

            byte[] sessionKey = ComputeSessionKeyAes(ntHash, clientChallenge, serverChallenge);
            byte[] clientCredential = ComputeNetlogonCredentialAes(clientChallenge, sessionKey);

            uint negotiateFlags = NegotiateFlagsAes;
            byte[] serverCredential = new byte[8];
            uint accountRid;

            rc = I_NetServerAuthenticate3(dcName, accountName, WorkstationSecureChannel, computerName,
                clientCredential, serverCredential, ref negotiateFlags, out accountRid);

            log("[*] Authenticate3 NTSTATUS=0x" + ((uint)rc).ToString("x8") +
                " ReturnedFlags=0x" + negotiateFlags.ToString("x8") +
                " AESbit=" + ((negotiateFlags & NETLOGON_NEG_SUPPORTS_AES) != 0));

            if (rc != 0)
                throw new System.ComponentModel.Win32Exception(rc,
                    "I_NetServerAuthenticate3 failed (NTSTATUS 0x" + ((uint)rc).ToString("x8") + ").");

            bool aes = (negotiateFlags & NETLOGON_NEG_SUPPORTS_AES) != 0;
            byte[] expected = ComputeNetlogonCredentialAes(serverChallenge, sessionKey);
            bool verified = ByteArrayEquals(expected, serverCredential);

            log("[+] Authenticate3 OK. NegotiateFlags=0x" + negotiateFlags.ToString("x8") +
                " AES=" + aes + " AccountRid=" + accountRid);
            log("[*] ServerCredential : " + ToHex(serverCredential));
            log("[*] Expected         : " + ToHex(expected));

            if (!aes)
                log("[!] WARNING: DC did not negotiate AES; this client only implements the AES credential path.");
            if (!verified)
                throw new Exception("Server credential verification FAILED — session-key mismatch " +
                                    "(wrong machine secret or crypto mismatch).");

            log("[+] Server credential VERIFIED — secure channel established.");

            return new SecureChannel
            {
                DcName = dcName,
                ComputerName = computerName,
                AccountName = accountName,
                SessionKey = sessionKey,
                ClientCredential = clientCredential,
                NegotiateFlags = negotiateFlags,
                AccountRid = accountRid,
                AesNegotiated = aes
            };
        }

        /// <summary>MS-NRPC 3.1.4.3.1: AES session key = HMAC-SHA256(NTOWFv1, clientChal || serverChal)[0..15].</summary>
        public static byte[] ComputeSessionKeyAes(byte[] ntHash, byte[] clientChallenge, byte[] serverChallenge)
        {
            using (var hmac = new HMACSHA256(ntHash))
            {
                byte[] data = new byte[16];
                Array.Copy(clientChallenge, 0, data, 0, 8);
                Array.Copy(serverChallenge, 0, data, 8, 8);
                byte[] full = hmac.ComputeHash(data);
                byte[] sessionKey = new byte[16];
                Array.Copy(full, 0, sessionKey, 0, 16);
                return sessionKey;
            }
        }

        /// <summary>
        /// MS-NRPC 3.1.4.4.1: AES credential = AES-128-CFB8(key=sessionKey, IV=0) over the 8-byte input.
        /// .NET's AesCryptoServiceProvider CFB8 rejects sub-block TransformFinalBlock, so CFB8 is
        /// implemented manually over AES-ECB (one byte per step), matching impacket segment_size=8.
        /// </summary>
        public static byte[] ComputeNetlogonCredentialAes(byte[] input8, byte[] sessionKey)
        {
            byte[] output = new byte[input8.Length];
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                aes.Key = sessionKey;
                using (var enc = aes.CreateEncryptor())
                {
                    byte[] feedback = new byte[16];   // IV = zeros
                    byte[] keystream = new byte[16];
                    for (int i = 0; i < input8.Length; i++)
                    {
                        enc.TransformBlock(feedback, 0, 16, keystream, 0);
                        byte cipherByte = (byte)(input8[i] ^ keystream[0]);
                        output[i] = cipherByte;
                        Array.Copy(feedback, 1, feedback, 0, 15);
                        feedback[15] = cipherByte;
                    }
                }
            }
            return output;
        }

        /// <summary>
        /// Load the machine secret from a file produced by LsaSecretExtractor.
        /// Accepts: 32-hex-char NTOWFv1, base64, or raw bytes; raw/cleartext is reduced via MD4.
        /// Returns the 16-byte NTOWFv1.
        /// </summary>
        public static byte[] LoadNtHash(string path)
        {
            byte[] raw = File.ReadAllBytes(path);
            string text = Encoding.ASCII.GetString(raw).Trim();

            if (text.Length >= 2 && text.Length % 2 == 0 && IsHexString(text))
            {
                byte[] bytes = HexToBytes(text);
                return bytes.Length == 16 ? bytes : Md4.Hash(bytes);
            }

            try
            {
                byte[] b64 = Convert.FromBase64String(text);
                return b64.Length == 16 ? b64 : Md4.Hash(b64);
            }
            catch (FormatException) { }

            return raw.Length == 16 ? raw : Md4.Hash(raw);
        }

        /// <summary>
        /// Isolates the AES-CFB8 implementation: compares the manual byte-wise CFB8 against
        /// .NET's own CFB8 on a full 16-byte block (where TransformFinalBlock is accepted).
        /// A match proves the credential crypto is correct, isolating any failure to the NT hash.
        /// </summary>
        public static void TestCrypto()
        {
            // MD4 RFC 1320 vectors, including multi-block inputs (>64 bytes) to catch block-chaining bugs.
            CheckMd4("", "31d6cfe0d16ae931b73c59d7e0c089c0");
            CheckMd4("abc", "a448017aaf21d8525fc10ae87aa6729d");
            CheckMd4("message digest", "d9130a8164549fe818874806e1c7014b");
            CheckMd4("abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9");
            CheckMd4("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4");
            CheckMd4("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536");

            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] key = new byte[16]; rng.GetBytes(key);
                byte[] input = new byte[16]; rng.GetBytes(input);

                byte[] manual = ComputeNetlogonCredentialAes(input, key);

                byte[] dotnet;
                using (var aes = new AesCryptoServiceProvider())
                {
                    aes.Mode = CipherMode.CFB;
                    aes.FeedbackSize = 8;
                    aes.Padding = PaddingMode.None;
                    aes.Key = key;
                    aes.IV = new byte[16];
                    using (var enc = aes.CreateEncryptor())
                        dotnet = enc.TransformFinalBlock(input, 0, 16);
                }

                Console.WriteLine("[*] Key        : " + ToHex(key));
                Console.WriteLine("[*] Input      : " + ToHex(input));
                Console.WriteLine("[*] Manual CFB8: " + ToHex(manual));
                Console.WriteLine("[*] .NET  CFB8 : " + ToHex(dotnet));
                Console.WriteLine(ToHex(manual) == ToHex(dotnet)
                    ? "[+] CFB8 MATCH — credential crypto is correct."
                    : "[!] CFB8 MISMATCH — manual implementation is wrong.");
            }
        }

        /// <summary>
        /// Brute-forces the correct NTOWFv1 derivation from a raw $MACHINE.ACC blob by trying several
        /// candidate slices (full / strip 4-byte prefix / strip trailing zero padding / combinations)
        /// against the live DC. The slice whose credential the DC verifies reveals the real structure.
        /// </summary>
        public static void TestSecureChannelRaw(string rawFile, string dcName)
        {
            try
            {
                if (string.IsNullOrEmpty(rawFile) || !File.Exists(rawFile))
                {
                    Console.WriteLine("[!] Usage: FindGT.exe --test-securechannel-raw <raw-secret-file> [dcName]");
                    return;
                }

                byte[] raw = LoadBytesFlexible(rawFile);
                Console.WriteLine("[*] Raw secret length: " + raw.Length + " bytes");

                if (string.IsNullOrEmpty(dcName))
                {
                    string domain = Environment.GetEnvironmentVariable("USERDNSDOMAIN");
                    dcName = LocateDc(domain);
                }
                Console.WriteLine("[*] DC: " + dcName);
                Console.WriteLine("[*] Computer: " + Environment.MachineName);
                Console.WriteLine();

                var candidates = new System.Collections.Generic.List<System.Collections.Generic.KeyValuePair<string, byte[]>>();
                candidates.Add(Cand("MD4(full)", raw));
                candidates.Add(Cand("MD4(trimZeros)", TrimTrailingZeros(raw)));
                candidates.Add(Cand("MD4(skip4)", Sub(raw, 4, raw.Length - 4)));
                candidates.Add(Cand("MD4(skip4,trimZeros)", TrimTrailingZeros(Sub(raw, 4, raw.Length - 4))));
                candidates.Add(Cand("MD4(skip16)", Sub(raw, 16, raw.Length - 16)));
                candidates.Add(Cand("MD4(skip16,trimZeros)", TrimTrailingZeros(Sub(raw, 16, raw.Length - 16))));
                candidates.Add(Cand("MD4(skip4,drop16tail)", Sub(raw, 4, raw.Length - 20)));
                candidates.Add(Cand("MD4(skip28)", Sub(raw, 28, raw.Length - 28)));
                candidates.Add(Cand("MD4(skip28,trimZeros)", TrimTrailingZeros(Sub(raw, 28, raw.Length - 28))));
                candidates.Add(Cand("MD4(seg4_21)", Sub(raw, 4, 18)));
                candidates.Add(Cand("MD4(seg2_21)", Sub(raw, 2, 20)));
                candidates.Add(Cand("MD4(seg28_315)", Sub(raw, 28, 288)));

                foreach (var c in candidates)
                {
                    Console.Write("[*] " + c.Key.PadRight(24) + " -> ");
                    try
                    {
                        SecureChannel sc = Establish(c.Value, dcName, Environment.MachineName, delegate { });
                        Console.WriteLine("SUCCESS (RID=" + sc.AccountRid + ", AES=" + sc.AesNegotiated + ")");
                        Console.WriteLine();
                        Console.WriteLine("[+] WINNER derivation: " + c.Key);
                        return;
                    }
                    catch (Exception ex)
                    {
                        string m = ex.Message;
                        int idx = m.IndexOf("NTSTATUS");
                        Console.WriteLine("fail" + (idx >= 0 ? " (" + m.Substring(idx, Math.Min(20, m.Length - idx)) + ")" : ""));
                    }
                }
                Console.WriteLine();
                Console.WriteLine("[!] No candidate derivation succeeded.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Raw secure-channel test FAILED: " + ex.Message);
            }
        }

        private static System.Collections.Generic.KeyValuePair<string, byte[]> Cand(string name, byte[] material)
        {
            return new System.Collections.Generic.KeyValuePair<string, byte[]>(name, Md4.Hash(material));
        }

        private static byte[] Sub(byte[] data, int offset, int length)
        {
            if (offset < 0) offset = 0;
            if (length < 0) length = 0;
            if (offset + length > data.Length) length = data.Length - offset;
            byte[] r = new byte[length];
            Array.Copy(data, offset, r, 0, length);
            return r;
        }

        private static byte[] TrimTrailingZeros(byte[] data)
        {
            int end = data.Length;
            while (end > 0 && data[end - 1] == 0) end--;
            return Sub(data, 0, end);
        }

        private static byte[] LoadBytesFlexible(string path)
        {
            byte[] raw = File.ReadAllBytes(path);
            string text = Encoding.ASCII.GetString(raw).Trim();
            if (text.Length >= 2 && text.Length % 2 == 0 && IsHexString(text))
                return HexToBytes(text);
            try { return Convert.FromBase64String(text); }
            catch (FormatException) { }
            return raw;
        }

        public static void TestSecureChannel(string hashFile, string dcName)
        {
            try
            {
                if (string.IsNullOrEmpty(hashFile) || !File.Exists(hashFile))
                {
                    Console.WriteLine("[!] Usage: FindGT.exe --test-securechannel <nthash-file> [dcName]");
                    if (!string.IsNullOrEmpty(hashFile))
                        Console.WriteLine("[!] Hash file not found: " + hashFile);
                    return;
                }

                byte[] ntHash = LoadNtHash(hashFile);
                Console.WriteLine("[*] Loaded machine secret (" + ntHash.Length + "-byte NTOWFv1) from " + hashFile);

                if (string.IsNullOrEmpty(dcName))
                {
                    string domain = Environment.GetEnvironmentVariable("USERDNSDOMAIN");
                    dcName = LocateDc(domain);
                    Console.WriteLine("[*] Located DC: " + dcName + " (domain " + domain + ")");
                }

                SecureChannel sc = Establish(ntHash, dcName, Environment.MachineName, Console.WriteLine);
                Console.WriteLine();
                Console.WriteLine("[+] SECURE CHANNEL OK (AES=" + sc.AesNegotiated + ", AccountRid=" + sc.AccountRid + ").");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Secure channel test FAILED: " + ex.Message);
            }
        }

        #region helpers

        private static void CheckMd4(string ascii, string expected)
        {
            string got = ToHex(Md4.Hash(Encoding.ASCII.GetBytes(ascii)));
            bool ok = string.Equals(got, expected, StringComparison.OrdinalIgnoreCase);
            Console.WriteLine("[" + (ok ? "+" : "!") + "] MD4(\"" + (ascii.Length > 16 ? ascii.Substring(0, 13) + "..." : ascii) +
                              "\") = " + got + (ok ? "  OK" : "  EXPECTED " + expected));
        }

        private static bool IsHexString(string s)
        {
            foreach (char c in s)
                if (!Uri.IsHexDigit(c)) return false;
            return s.Length > 0;
        }

        private static byte[] HexToBytes(string hex)
        {
            byte[] b = new byte[hex.Length / 2];
            for (int i = 0; i < b.Length; i++)
                b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return b;
        }

        public static string ToHex(byte[] data)
        {
            var sb = new StringBuilder(data.Length * 2);
            foreach (byte b in data)
                sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        private static bool ByteArrayEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }

        #endregion
    }
}
