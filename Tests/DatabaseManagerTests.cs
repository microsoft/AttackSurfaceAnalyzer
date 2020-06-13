using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace AttackSurfaceAnalyzer.Tests
{
    [TestClass]
    public class DatabaseManagerTests
    {
        [ClassInitialize]
        public static void ClassSetup(TestContext _)
        {
            Logger.Setup(false, true);
            Strings.Setup();
            AsaTelemetry.Setup(test: true);
        }

        public static FileSystemObject GetRandomObject(int ObjectPadding = 0)
        {
            return new FileSystemObject(CryptoHelpers.GetRandomString(32))
            {
                // Pad this field with extra data.
                FileType = CryptoHelpers.GetRandomString(ObjectPadding),
            };
        }

        [TestCleanup]
        public void Cleanup()
        {
            DatabaseManager.Destroy();
        }

        [TestMethod]
        public void TestGetLatestRunIds()
        {
            DatabaseManager.Setup("asa.sqlite");
            var run1 = new AsaRun("Run1", DateTime.Now, "Version", AsaHelpers.GetPlatform(), new List<RESULT_TYPE>() { RESULT_TYPE.CERTIFICATE }, RUN_TYPE.COLLECT);
            var run2 = new AsaRun("Run2", DateTime.Now, "Version", AsaHelpers.GetPlatform(), new List<RESULT_TYPE>() { RESULT_TYPE.CERTIFICATE }, RUN_TYPE.COLLECT);
            var run3 = new AsaRun("Run3", DateTime.Now, "Version", AsaHelpers.GetPlatform(), new List<RESULT_TYPE>() { RESULT_TYPE.CERTIFICATE }, RUN_TYPE.COLLECT);

            DatabaseManager.InsertRun(run1);
            DatabaseManager.InsertRun(run2);
            DatabaseManager.InsertRun(run3);

            var runids = DatabaseManager.GetLatestRunIds(10, RUN_TYPE.COLLECT);

            Assert.IsTrue(runids.Count == 3);
        }

        [TestMethod]
        public void TestGetRun()
        {
            DatabaseManager.Setup("asa.sqlite");
            var run1 = new AsaRun("Run1", DateTime.Now, "Version", AsaHelpers.GetPlatform(), new List<RESULT_TYPE>() { RESULT_TYPE.CERTIFICATE }, RUN_TYPE.COLLECT);

            DatabaseManager.InsertRun(run1);

            var run2 = DatabaseManager.GetRun("Run1");

            Assert.IsTrue(run1.Version == run2?.Version);
        }

        [TestMethod]
        public void TestGetSetSettings()
        {
            DatabaseManager.Setup("asa.sqlite", new DBSettings() { ShardingFactor = 1 });

            Settings settings = new Settings()
            {
                SchemaVersion = 10,
                ShardingFactor = 10,
                TelemetryEnabled = false
            };

            DatabaseManager.SetSettings(settings);

            var settingsOut = DatabaseManager.GetSettings();

            Assert.IsNotNull(settingsOut);
            Assert.IsTrue(settings.SchemaVersion == settingsOut?.SchemaVersion);
            Assert.IsTrue(settings.ShardingFactor == settingsOut?.ShardingFactor);
            Assert.IsTrue(settings.TelemetryEnabled == settingsOut?.TelemetryEnabled);
        }

        [TestMethod]
        public void TestInsertAndReadBack()
        {
            DatabaseManager.Setup("asa.sqlite", new DBSettings() { ShardingFactor = 1 });
            var co = new CertificateObject("StoreLocation", "StoreName", new SerializableCertificate("Thumbprint", "Subject", "PublicKey", DateTime.Now.AddYears(1), DateTime.Now, "Issuer", "SerialNumber", "CertHashString", "Pkcs7"));
            var runId = "TestRun";
            var numberOfObjects = 100;
            DatabaseManager.Write(co, runId);

            while (DatabaseManager.HasElements)
            {
                Thread.Sleep(1);
            }

            Assert.IsTrue(DatabaseManager.GetResultsByRunid(runId).Any(x => x.ColObj is CertificateObject co && co.StoreLocation == "StoreLocation"));

            for (int i = 0; i < numberOfObjects; i++)
            {
                DatabaseManager.Write(GetRandomObject(), runId);
            }

            while (DatabaseManager.HasElements)
            {
                Thread.Sleep(1);
            }

            Assert.IsTrue(DatabaseManager.GetResultsByRunid(runId).Count(x => x.ColObj.ResultType == RESULT_TYPE.FILE) == numberOfObjects);
        }

        [TestMethod]
        public void TestRunIdToPlatform()
        {
            DatabaseManager.Setup("asa.sqlite");
            var run1 = new AsaRun("Run1", DateTime.Now, "Version", AsaHelpers.GetPlatform(), new List<RESULT_TYPE>() { RESULT_TYPE.CERTIFICATE }, RUN_TYPE.COLLECT);

            DatabaseManager.InsertRun(run1);

            var platform = DatabaseManager.RunIdToPlatform("Run1");

            Assert.IsTrue(run1.Platform == platform);
        }

        [TestMethod]
        public void TestTrimToLatest()
        {
            DatabaseManager.Setup("asa.sqlite");
            var compareRun = new AsaRun("Run1", DateTime.Now, "Version", AsaHelpers.GetPlatform(), new List<RESULT_TYPE>() { RESULT_TYPE.CERTIFICATE }, RUN_TYPE.COMPARE);
            var run1 = new AsaRun("Run1", DateTime.Now, "Version", AsaHelpers.GetPlatform(), new List<RESULT_TYPE>() { RESULT_TYPE.CERTIFICATE }, RUN_TYPE.COLLECT);
            var run2 = new AsaRun("Run2", DateTime.Now, "Version", AsaHelpers.GetPlatform(), new List<RESULT_TYPE>() { RESULT_TYPE.CERTIFICATE }, RUN_TYPE.COLLECT);
            var run3 = new AsaRun("Run3", DateTime.Now, "Version", AsaHelpers.GetPlatform(), new List<RESULT_TYPE>() { RESULT_TYPE.CERTIFICATE }, RUN_TYPE.COLLECT);

            // TODO: Write results in and then trim them

            DatabaseManager.InsertRun(compareRun);
            DatabaseManager.InsertRun(run1);
            DatabaseManager.InsertRun(run2);
            DatabaseManager.InsertRun(run3);

            DatabaseManager.TrimToLatest();

            Assert.IsTrue(DatabaseManager.GetRuns(RUN_TYPE.COLLECT).Count == 1);
        }
    }
}