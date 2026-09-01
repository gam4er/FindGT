using System;
using System.Globalization;
using System.Runtime.InteropServices;

namespace FindGT
{
    [StructLayout(LayoutKind.Sequential)]
    public struct LUID : IEquatable<LUID>
    {
        public UInt32 LowPart;
        public Int32 HighPart;

        public ulong Value
        {
            get { return ((UInt64)(UInt32)HighPart << 32) | LowPart; }
        }

        public LUID(UInt64 value)
        {
            LowPart = (UInt32)(value & UInt32.MaxValue);
            HighPart = (Int32)(value >> 32);
        }

        public LUID(LUID value)
        {
            LowPart = value.LowPart;
            HighPart = value.HighPart;
        }

        public LUID(string value)
        {
            LUID parsed;
            if (!TryParse(value, out parsed))
            {
                throw new FormatException("LUID must be an unsigned decimal value or a hexadecimal value prefixed with 0x.");
            }

            LowPart = parsed.LowPart;
            HighPart = parsed.HighPart;
        }

        public override int GetHashCode()
        {
            return Value.GetHashCode();
        }

        public bool Equals(LUID other)
        {
            return Value == other.Value;
        }

        public override bool Equals(object obj)
        {
            return obj is LUID && Equals((LUID)obj);
        }

        public byte[] GetBytes()
        {
            byte[] bytes = new byte[8];

            byte[] lowBytes = BitConverter.GetBytes(LowPart);
            byte[] highBytes = BitConverter.GetBytes(HighPart);

            Array.Copy(lowBytes, 0, bytes, 0, 4);
            Array.Copy(highBytes, 0, bytes, 4, 4);

            return bytes;
        }

        public override string ToString()
        {
            return String.Format(CultureInfo.InvariantCulture, "0x{0:X16}", Value);
        }

        public static LUID Parse(string value)
        {
            return new LUID(value);
        }

        public static bool TryParse(string value, out LUID luid)
        {
            luid = default(LUID);
            if (String.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            UInt64 parsed;
            string candidate = value.Trim();
            if (candidate.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                candidate = candidate.Substring(2);
                if (candidate.Length == 0 ||
                    !UInt64.TryParse(candidate, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out parsed))
                {
                    return false;
                }
            }
            else if (!UInt64.TryParse(candidate, NumberStyles.None, CultureInfo.InvariantCulture, out parsed))
            {
                return false;
            }

            luid = new LUID(parsed);
            return true;
        }

        public static bool operator ==(LUID x, LUID y)
        {
            return x.Equals(y);
        }

        public static bool operator !=(LUID x, LUID y)
        {
            return !x.Equals(y);
        }

        public static implicit operator ulong(LUID luid)
        {
            return luid.Value;
        }
    }
}
