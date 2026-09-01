using System;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using FindGT.Core;
using FindGT.Eventing;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FindGT.Tests
{
    [TestClass]
    public sealed class EventingInfrastructureTests
    {
        [TestMethod]
        public void BoundedQueueRejectsOverflowWithoutBlocking()
        {
            using (BoundedSessionQueue queue = new BoundedSessionQueue(1))
            {
                Assert.IsTrue(queue.TryEnqueue(Candidate(1)));
                Assert.IsFalse(queue.TryEnqueue(Candidate(2)));
                Assert.AreEqual(1, queue.Count);
            }
        }

        [TestMethod]
        public void DedupeUsesFullLuidAndBootInstance()
        {
            Guid boot = Guid.NewGuid();
            SessionDeduplicator dedupe =
                new SessionDeduplicator(TimeSpan.FromHours(24));
            SessionIdentityKey lowOnly = new SessionIdentityKey(
                "VICTIM",
                boot,
                new LUID(0x0000000012345678));
            SessionIdentityKey highPart = new SessionIdentityKey(
                "victim",
                boot,
                new LUID(0x0000000112345678));

            Assert.IsTrue(dedupe.TryBegin(lowOnly));
            Assert.IsFalse(dedupe.TryBegin(lowOnly));
            Assert.IsTrue(dedupe.TryBegin(highPart));
        }

        [TestMethod]
        public void CompletedEntryExpiresAfterTtl()
        {
            DateTime now = new DateTime(
                2026,
                9,
                1,
                18,
                0,
                0,
                DateTimeKind.Utc);
            SessionDeduplicator dedupe = new SessionDeduplicator(
                TimeSpan.FromHours(24),
                delegate { return now; });
            SessionIdentityKey key = new SessionIdentityKey(
                "VICTIM",
                Guid.NewGuid(),
                new LUID(1));

            Assert.IsTrue(dedupe.TryBegin(key));
            dedupe.MarkCompleted(key);
            Assert.IsFalse(dedupe.TryBegin(key));

            now = now.AddHours(25);
            Assert.IsTrue(dedupe.TryBegin(key));
        }

        [TestMethod]
        public void BookmarkStoreRoundTripsFrameworkBookmarkXml()
        {
            string directory = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "FindGT.Tests",
                Guid.NewGuid().ToString("N"));
            string path = System.IO.Path.Combine(directory, "Security.bookmark.xml");
            const string xml =
                "<BookmarkList><Bookmark Channel='Security' RecordId='42' IsCurrent='true'/></BookmarkList>";

            try
            {
                EventBookmarkStore store = new EventBookmarkStore(path);
                EventBookmark original = EventBookmarkCompatibility.FromXml(xml);
                store.Save(original);

                EventBookmark loaded;
                string error;
                Assert.IsTrue(store.TryLoad(out loaded, out error), error);
                Assert.AreEqual(xml, EventBookmarkCompatibility.ToXml(loaded));
            }
            finally
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }

                if (Directory.Exists(directory))
                {
                    Directory.Delete(directory, true);
                }
            }
        }

        [TestMethod]
        public void BookmarkStoreFallsBackToLastKnownGoodBackup()
        {
            string directory = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "FindGT.Tests",
                Guid.NewGuid().ToString("N"));
            string path = System.IO.Path.Combine(directory, "Security.bookmark.xml");
            const string first =
                "<BookmarkList><Bookmark Channel='Security' RecordId='42' IsCurrent='true'/></BookmarkList>";
            const string second =
                "<BookmarkList><Bookmark Channel='Security' RecordId='43' IsCurrent='true'/></BookmarkList>";

            try
            {
                EventBookmarkStore store = new EventBookmarkStore(path);
                store.Save(EventBookmarkCompatibility.FromXml(first));
                store.Save(EventBookmarkCompatibility.FromXml(second));
                File.WriteAllText(path, "<invalid");

                EventBookmark loaded;
                string warning;
                Assert.IsTrue(store.TryLoad(out loaded, out warning), warning);
                StringAssert.Contains(warning, "last-known-good backup");
                Assert.AreEqual(first, EventBookmarkCompatibility.ToXml(loaded));
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
        public void ReplayQueryUsesBoundedTimeWindow()
        {
            string query = SecurityEventLogSource.BuildQuery(
                TimeSpan.FromHours(24));

            StringAssert.Contains(query, "EventID=4624");
            StringAssert.Contains(
                query,
                "timediff(@SystemTime) <= 86400000");
        }

        private static SessionCandidate Candidate(ulong value)
        {
            return new SessionCandidate
            {
                LogonId = new LUID(value),
                Trigger = SessionTriggerContext.ForCli()
            };
        }
    }
}
