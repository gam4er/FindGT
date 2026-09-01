using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using FindGT.Core;
using FindGT.Eventing;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FindGT.Tests
{
    [TestClass]
    public sealed class EventSinkTests
    {
        [TestMethod]
        public void AnalysisPayloadIsBoundedAndOmitsCredentialArtifacts()
        {
            SessionAnalysisResult result = Result();
            result.Session.CredentialUserName = "DO-NOT-SERIALIZE";
            for (int index = 0; index < 5000; index++)
            {
                result.TokenGroups.Add(new TokenGroupInfo
                {
                    Sid = TestFixtures.DomainSid + "-" + (2000 + index),
                    Attributes = 4
                });
            }

            string payload = AnalysisPayloadSerializer.SerializeAnalysis(result);

            Assert.IsTrue(result.PayloadTruncated);
            Assert.IsTrue(payload.Length <= 30000);
            Assert.IsFalse(payload.Contains("DO-NOT-SERIALIZE"));
            StringAssert.Contains(payload, result.AnalysisId.ToString("D"));
        }

        [TestMethod]
        public void JsonSinkWritesUtf8WithoutBom()
        {
            string directory = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "FindGT.Tests",
                Guid.NewGuid().ToString("N"));
            try
            {
                using (JsonResultSink sink = new JsonResultSink(directory))
                {
                    string error;
                    Assert.IsTrue(sink.WriteAnalysis(Result(), out error), error);
                }

                string[] files = Directory.GetFiles(directory, "*.jsonl");
                Assert.AreEqual(1, files.Length);
                byte[] bytes = File.ReadAllBytes(files[0]);
                Assert.IsFalse(
                    bytes.Length >= 3 &&
                    bytes[0] == 0xEF &&
                    bytes[1] == 0xBB &&
                    bytes[2] == 0xBF);
                string text = Encoding.UTF8.GetString(bytes);
                StringAssert.Contains(text, "\"SchemaVersion\":1");
            }
            finally
            {
                if (Directory.Exists(directory))
                {
                    Directory.Delete(directory, true);
                }
            }
        }

        [TestMethod]
        public void AuthzAuditStructuresMatchX64WindowsAbi()
        {
            Assert.AreEqual(8, IntPtr.Size);
            Assert.AreEqual(
                32,
                Marshal.SizeOf(typeof(AuthzSecurityEventSink.AuditParam)));
            Assert.AreEqual(
                24,
                Marshal.SizeOf(typeof(AuthzSecurityEventSink.AuditParams)));
        }

        [TestMethod]
        public void SecurityModeParsingIsCaseInsensitive()
        {
            SecuritySinkMode mode;
            Assert.IsTrue(
                AuthzSecurityEventSink.TryParseMode("suspiciousonly", out mode));
            Assert.AreEqual(SecuritySinkMode.SuspiciousOnly, mode);
            Assert.IsFalse(
                AuthzSecurityEventSink.TryParseMode("invalid", out mode));
        }

        private static SessionAnalysisResult Result()
        {
            return new SessionAnalysisResult
            {
                ProductVersion = "1.0.0.0",
                ComputerName = "VICTIM",
                BootInstanceId = Guid.NewGuid(),
                Trigger = SessionTriggerContext.ForCli(),
                Session = TestFixtures.Session(1),
                ReferenceProvider = "S4U2Self",
                ReferenceSucceeded = true,
                Verdict = AnalysisVerdict.Clean,
                ProcessingStatus = ProcessingStatus.Completed
            };
        }
    }
}
