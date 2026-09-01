using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FindGT.Tests
{
    [TestClass]
    public sealed class LuidTests
    {
        [DataTestMethod]
        [DataRow(0UL)]
        [DataRow(0x12345678UL)]
        [DataRow(0x0000000112345678UL)]
        [DataRow(0x7FFFFFFFFFFFFFFFUL)]
        [DataRow(0xFFFFFFFFFFFFFFFFUL)]
        public void ValueRoundTripsAllBits(ulong value)
        {
            LUID luid = new LUID(value);

            Assert.AreEqual(value, luid.Value);
            Assert.AreEqual(value, (ulong)luid);
            Assert.AreEqual(value, LUID.Parse(luid.ToString()).Value);
            Assert.AreEqual("0x" + value.ToString("X16"), luid.ToString());
        }

        [TestMethod]
        public void ParsesDecimalAndHexadecimal()
        {
            Assert.AreEqual(
                0x0000000112345678UL,
                LUID.Parse("0x0000000112345678").Value);
            Assert.AreEqual(305419896UL, LUID.Parse("305419896").Value);
        }

        [TestMethod]
        public void RejectsMalformedInput()
        {
            LUID ignored;
            Assert.IsFalse(LUID.TryParse(null, out ignored));
            Assert.IsFalse(LUID.TryParse("0x", out ignored));
            Assert.IsFalse(LUID.TryParse("-1", out ignored));
            Assert.ThrowsExactly<FormatException>(
                delegate { LUID.Parse("not-a-luid"); });
        }

        [TestMethod]
        public void EqualityAndHashCodeUseFullValue()
        {
            LUID lowOnly = new LUID(0x0000000012345678UL);
            LUID withHighPart = new LUID(0x0000000112345678UL);

            Assert.AreNotEqual(lowOnly, withHighPart);
            Assert.AreNotEqual(lowOnly.GetHashCode(), withHighPart.GetHashCode());
        }
    }
}
