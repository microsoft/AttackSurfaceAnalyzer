using AttackSurfaceAnalyzer.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;

namespace AttackSurfaceAnalyzer.Tests
{
    [TestClass]
    public class AnalyzerTests
    {
        public void Setup()
        {
            Logger.Setup(false, true);
            Strings.Setup();
            AsaTelemetry.Setup(test: true);
            DatabaseManager.Setup(Path.GetTempFileName());
        }

        public void TearDown()
        {
            DatabaseManager.Destroy();
        }

        [TestMethod]
        public void VerifyEmbeddedRulesAreValid()
        {
            Setup();

            var analyzer = new Analyzer(AsaHelpers.GetPlatform(), null);
            Assert.IsTrue(analyzer.VerifyRules());

            TearDown();
        }
    }
}
