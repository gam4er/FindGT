using System;

namespace FindGT
{
    /// <summary>
    /// RFC 1320 MD4 implementation. .NET does not ship MD4, but it is required for
    /// NTOWFv1 = MD4(UTF-16LE(password)), which is the machine-account credential used
    /// to derive the Netlogon secure-channel session key.
    /// Verified against RFC 1320 test vectors:
    ///   MD4("")    = 31d6cfe0d16ae931b73c59d7e0c089c0
    ///   MD4("abc") = a448017aaf21d8525fc10ae87aa6729d
    /// </summary>
    public static class Md4
    {
        public static byte[] Hash(byte[] input)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));

            uint a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;

            long originalLengthBits = (long)input.Length * 8;
            int padLen = (56 - (input.Length + 1) % 64 + 64) % 64;
            byte[] msg = new byte[input.Length + 1 + padLen + 8];
            Array.Copy(input, msg, input.Length);
            msg[input.Length] = 0x80;
            for (int i = 0; i < 8; i++)
                msg[msg.Length - 8 + i] = (byte)((originalLengthBits >> (8 * i)) & 0xff);

            uint[] x = new uint[16];
            for (int off = 0; off < msg.Length; off += 64)
            {
                for (int i = 0; i < 16; i++)
                    x[i] = (uint)(msg[off + i * 4]
                               | (msg[off + i * 4 + 1] << 8)
                               | (msg[off + i * 4 + 2] << 16)
                               | (msg[off + i * 4 + 3] << 24));

                uint aa = a, bb = b, cc = c, dd = d;

                // Round 1
                a = FF(a, b, c, d, x[0], 3); d = FF(d, a, b, c, x[1], 7); c = FF(c, d, a, b, x[2], 11); b = FF(b, c, d, a, x[3], 19);
                a = FF(a, b, c, d, x[4], 3); d = FF(d, a, b, c, x[5], 7); c = FF(c, d, a, b, x[6], 11); b = FF(b, c, d, a, x[7], 19);
                a = FF(a, b, c, d, x[8], 3); d = FF(d, a, b, c, x[9], 7); c = FF(c, d, a, b, x[10], 11); b = FF(b, c, d, a, x[11], 19);
                a = FF(a, b, c, d, x[12], 3); d = FF(d, a, b, c, x[13], 7); c = FF(c, d, a, b, x[14], 11); b = FF(b, c, d, a, x[15], 19);

                // Round 2
                a = GG(a, b, c, d, x[0], 3); d = GG(d, a, b, c, x[4], 5); c = GG(c, d, a, b, x[8], 9); b = GG(b, c, d, a, x[12], 13);
                a = GG(a, b, c, d, x[1], 3); d = GG(d, a, b, c, x[5], 5); c = GG(c, d, a, b, x[9], 9); b = GG(b, c, d, a, x[13], 13);
                a = GG(a, b, c, d, x[2], 3); d = GG(d, a, b, c, x[6], 5); c = GG(c, d, a, b, x[10], 9); b = GG(b, c, d, a, x[14], 13);
                a = GG(a, b, c, d, x[3], 3); d = GG(d, a, b, c, x[7], 5); c = GG(c, d, a, b, x[11], 9); b = GG(b, c, d, a, x[15], 13);

                // Round 3
                a = HH(a, b, c, d, x[0], 3); d = HH(d, a, b, c, x[8], 9); c = HH(c, d, a, b, x[4], 11); b = HH(b, c, d, a, x[12], 15);
                a = HH(a, b, c, d, x[2], 3); d = HH(d, a, b, c, x[10], 9); c = HH(c, d, a, b, x[6], 11); b = HH(b, c, d, a, x[14], 15);
                a = HH(a, b, c, d, x[1], 3); d = HH(d, a, b, c, x[9], 9); c = HH(c, d, a, b, x[5], 11); b = HH(b, c, d, a, x[13], 15);
                a = HH(a, b, c, d, x[3], 3); d = HH(d, a, b, c, x[11], 9); c = HH(c, d, a, b, x[7], 11); b = HH(b, c, d, a, x[15], 15);

                a += aa; b += bb; c += cc; d += dd;
            }

            byte[] result = new byte[16];
            WriteLittleEndian(result, 0, a);
            WriteLittleEndian(result, 4, b);
            WriteLittleEndian(result, 8, c);
            WriteLittleEndian(result, 12, d);
            return result;
        }

        private static uint F(uint x, uint y, uint z) { return (x & y) | (~x & z); }
        private static uint G(uint x, uint y, uint z) { return (x & y) | (x & z) | (y & z); }
        private static uint H(uint x, uint y, uint z) { return x ^ y ^ z; }
        private static uint Rol(uint x, int n) { return (x << n) | (x >> (32 - n)); }
        private static uint FF(uint a, uint b, uint c, uint d, uint xk, int s) { return Rol(a + F(b, c, d) + xk, s); }
        private static uint GG(uint a, uint b, uint c, uint d, uint xk, int s) { return Rol(a + G(b, c, d) + xk + 0x5a827999u, s); }
        private static uint HH(uint a, uint b, uint c, uint d, uint xk, int s) { return Rol(a + H(b, c, d) + xk + 0x6ed9eba1u, s); }

        private static void WriteLittleEndian(byte[] buffer, int offset, uint value)
        {
            buffer[offset] = (byte)value;
            buffer[offset + 1] = (byte)(value >> 8);
            buffer[offset + 2] = (byte)(value >> 16);
            buffer[offset + 3] = (byte)(value >> 24);
        }
    }
}
