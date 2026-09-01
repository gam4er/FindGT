using FindGT.Eventing;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FindGT.Tests
{
    [TestClass]
    public sealed class Event4624ParserTests
    {
        [TestMethod]
        public void ParsesNamedFieldsAndFullLuidRegardlessOfOrder()
        {
            string xml = EventXml(
                "<Data Name=\"IpAddress\">-</Data>" +
                "<Data Name=\"UnknownFutureField\">ignored</Data>" +
                "<Data Name=\"TargetLogonId\">0x0000000112345678</Data>" +
                "<Data Name=\"AuthenticationPackageName\">Negotiate</Data>" +
                "<Data Name=\"TargetDomainName\">CONTOSO</Data>" +
                "<Data Name=\"LogonType\">3</Data>" +
                "<Data Name=\"TargetUserName\">testuser</Data>" +
                "<Data Name=\"TargetUserSid\">" + TestFixtures.UserSid + "</Data>" +
                "<Data Name=\"LinkedLogonId\">0x0</Data>" +
                "<Data Name=\"LogonGuid\">{11111111-2222-3333-4444-555555555555}</Data>");

            SessionCandidate candidate = Event4624Parser.Parse(xml);

            Assert.AreEqual(0x0000000112345678UL, candidate.LogonId.Value);
            Assert.AreEqual(42L, candidate.Trigger.EventRecordId);
            Assert.AreEqual((uint)3, candidate.Trigger.LogonType);
            Assert.AreEqual("Negotiate", candidate.Trigger.AuthenticationPackage);
            Assert.AreEqual("testuser", candidate.Trigger.TargetUserName);
            Assert.IsNull(candidate.Trigger.IpAddress);
            Assert.AreEqual(0UL, candidate.Trigger.LinkedLogonId.Value.Value);
        }

        [TestMethod]
        public void MissingOptionalNetworkFieldsAreAllowed()
        {
            string xml = EventXml(
                "<Data Name=\"TargetLogonId\">0x1234</Data>" +
                "<Data Name=\"LogonType\">10</Data>");

            SessionCandidate candidate = Event4624Parser.Parse(xml);

            Assert.AreEqual(0x1234UL, candidate.LogonId.Value);
            Assert.IsNull(candidate.Trigger.IpAddress);
            Assert.IsNull(candidate.Trigger.WorkstationName);
        }

        [TestMethod]
        public void InvalidXmlAndInvalidLuidAreRejected()
        {
            SessionCandidate candidate;
            string error;
            Assert.IsFalse(Event4624Parser.TryParse(
                "<Event>",
                out candidate,
                out error));
            StringAssert.Contains(error, "invalid");

            Assert.IsFalse(Event4624Parser.TryParse(
                EventXml(
                    "<Data Name=\"TargetLogonId\">not-a-luid</Data>" +
                    "<Data Name=\"LogonType\">3</Data>"),
                out candidate,
                out error));
            StringAssert.Contains(error, "TargetLogonId");
        }

        [TestMethod]
        public void WrongProviderIsRejected()
        {
            string xml = EventXml(
                "<Data Name=\"TargetLogonId\">0x1</Data>" +
                "<Data Name=\"LogonType\">3</Data>")
                .Replace(
                    "Microsoft-Windows-Security-Auditing",
                    "Unexpected-Provider");

            Assert.ThrowsExactly<EventParseException>(
                delegate { Event4624Parser.Parse(xml); });
        }

        [TestMethod]
        public void MalformedOptionalIdentityFieldsAreRejected()
        {
            Assert.ThrowsExactly<EventParseException>(
                delegate
                {
                    Event4624Parser.Parse(EventXml(
                        "<Data Name=\"TargetLogonId\">0x1</Data>" +
                        "<Data Name=\"LogonType\">3</Data>" +
                        "<Data Name=\"LinkedLogonId\">invalid</Data>"));
                });
        }

        private static string EventXml(string data)
        {
            return
                "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">" +
                "<System>" +
                "<Provider Name=\"Microsoft-Windows-Security-Auditing\" />" +
                "<EventID>4624</EventID>" +
                "<TimeCreated SystemTime=\"2026-09-01T18:00:00.0000000Z\" />" +
                "<EventRecordID>42</EventRecordID>" +
                "</System>" +
                "<EventData>" + data + "</EventData>" +
                "</Event>";
        }
    }
}
