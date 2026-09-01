using System;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace FindGT.Core.Analysis
{
    internal static class BootInstanceIdProvider
    {
        private static readonly Lazy<Guid> CurrentValue =
            new Lazy<Guid>(Create, true);

        internal static Guid Current
        {
            get { return CurrentValue.Value; }
        }

        [DllImport("kernel32.dll")]
        private static extern ulong GetTickCount64();

        private static Guid Create()
        {
            string machineId = ReadRegistryValue(
                Registry.LocalMachine,
                @"SOFTWARE\Microsoft\Cryptography",
                "MachineGuid") ?? Environment.MachineName;
            string bootId = ReadRegistryValue(
                Registry.LocalMachine,
                @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters",
                "BootId");

            if (String.IsNullOrWhiteSpace(bootId))
            {
                DateTime estimatedBootUtc = DateTime.UtcNow.Subtract(
                    TimeSpan.FromMilliseconds(GetTickCount64()));
                long roundedMinuteTicks =
                    estimatedBootUtc.Ticks - (estimatedBootUtc.Ticks % TimeSpan.TicksPerMinute);
                bootId = roundedMinuteTicks.ToString(CultureInfo.InvariantCulture);
            }

            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] digest = sha256.ComputeHash(
                    Encoding.UTF8.GetBytes(machineId + "|" + bootId));
                byte[] guidBytes = new byte[16];
                Buffer.BlockCopy(digest, 0, guidBytes, 0, guidBytes.Length);
                return new Guid(guidBytes);
            }
        }

        private static string ReadRegistryValue(
            RegistryKey root,
            string path,
            string valueName)
        {
            try
            {
                using (RegistryKey key = root.OpenSubKey(path, false))
                {
                    object value = key == null ? null : key.GetValue(valueName);
                    return value == null
                        ? null
                        : Convert.ToString(value, CultureInfo.InvariantCulture);
                }
            }
            catch (SecurityException)
            {
                return null;
            }
            catch (UnauthorizedAccessException)
            {
                return null;
            }
            catch (IOException)
            {
                return null;
            }
        }
    }
}
