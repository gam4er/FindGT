using System;
using System.IO;
using FindGT.Service.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FindGT.Tests
{
    [TestClass]
    public sealed class ServiceConfigurationTests
    {
        [TestMethod]
        public void DefaultsMatchProductionPolicy()
        {
            ServiceConfiguration configuration =
                ServiceConfiguration.CreateDefault();

            Assert.AreEqual(1, configuration.SchemaVersion);
            CollectionAssert.AreEqual(
                new[] { 3, 10 },
                configuration.EnabledLogonTypes);
            Assert.IsTrue(configuration.AnalyzeExistingSessionsOnStart);
            Assert.AreEqual(1024, configuration.Queue.Capacity);
            Assert.AreEqual(1, configuration.Queue.WorkerCount);
            Assert.IsFalse(configuration.PowerfulOnly.Enabled);
            Assert.IsFalse(configuration.Output.Json.Enabled);
            Assert.AreEqual(
                "SuspiciousOnly",
                configuration.Output.SecurityEventLog.Mode);
            Assert.AreEqual(
                0,
                ServiceConfigurationLoader.Validate(configuration).Count);
        }

        [TestMethod]
        public void InvalidConfigurationUsesSafeDefaults()
        {
            string path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "FindGT.Tests." + Guid.NewGuid().ToString("N") + ".json");
            try
            {
                File.WriteAllText(
                    path,
                    "{\"SchemaVersion\":99,\"PowerfulOnly\":{\"Enabled\":true}}");
                ConfigurationLoadResult result =
                    new ServiceConfigurationLoader().Load(path);

                Assert.IsFalse(result.IsValid);
                Assert.IsTrue(result.UsedDefaults);
                Assert.IsFalse(result.Configuration.PowerfulOnly.Enabled);
                Assert.IsFalse(result.Configuration.Output.Json.Enabled);
                CollectionAssert.AreEqual(
                    new[] { 3, 10 },
                    result.Configuration.EnabledLogonTypes);
            }
            finally
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
        }

        [TestMethod]
        public void MissingConfigurationUsesSafeDefaults()
        {
            string path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "FindGT.Tests." + Guid.NewGuid().ToString("N") + ".missing");

            ConfigurationLoadResult result =
                new ServiceConfigurationLoader().Load(path);

            Assert.IsTrue(result.IsValid);
            Assert.IsTrue(result.UsedDefaults);
            Assert.IsFalse(result.Configuration.PowerfulOnly.Enabled);
        }

        [TestMethod]
        public void ValidationRejectsUnsupportedTypesAndUnsafeOutput()
        {
            ServiceConfiguration configuration =
                ServiceConfiguration.CreateDefault();
            configuration.EnabledLogonTypes = new[] { 3, 7 };
            configuration.Output.OperationalEventLog.Enabled = false;

            var errors = ServiceConfigurationLoader.Validate(configuration);

            Assert.IsTrue(errors.Count >= 2);
        }

        [TestMethod]
        public void ValidationRejectsJsonOutsideProtectedProgramData()
        {
            ServiceConfiguration configuration =
                ServiceConfiguration.CreateDefault();
            configuration.Output.Json.Enabled = true;
            configuration.Output.Json.Directory =
                System.IO.Path.GetTempPath();

            var errors = ServiceConfigurationLoader.Validate(configuration);

            Assert.IsTrue(errors.Count >= 1);
        }
    }
}
