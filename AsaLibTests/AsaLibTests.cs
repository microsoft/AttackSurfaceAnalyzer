using System.Collections.Generic;
using System.IO;
using System.Linq;
using AttackSurfaceAnalyzer.Collectors;
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;


namespace AsaTests
{
    [TestClass]
    public class AsaLibTests
    {
        [TestMethod]
        public void TestFileCollector()
        {
            Strings.Setup();

            DatabaseManager.SqliteFilename = Path.GetTempFileName();
            DatabaseManager.Setup();
            var FirstRunId = "TestFileCollector-1";
            var SecondRunId = "TestFileCollector-2";
            var fsc = new FileSystemCollector(FirstRunId, enableHashing: true, directories: Path.GetTempPath(), downloadCloud: false, examineCertificates: true);
            fsc.Execute();

            var testFile = Path.GetTempFileName();

            fsc = new FileSystemCollector(SecondRunId, enableHashing: true, directories: Path.GetTempPath(), downloadCloud: false, examineCertificates: true);
            fsc.Execute();

            BaseCompare bc = new BaseCompare();
            var watch = System.Diagnostics.Stopwatch.StartNew();
            if (!bc.TryCompare(FirstRunId, SecondRunId))
            {
                Assert.Fail();
            }

            Dictionary<string, List<CompareResult>> results = bc.Results;
            Assert.IsTrue(results["FILES_CREATED"].Where(x => x.Identity.Contains(testFile)).Count() > 0);
        }
    }
}
