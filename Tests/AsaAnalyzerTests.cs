using System.Collections.Generic;
using System.Linq;
using AttackSurfaceAnalyzer.Cli;
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using DiscUtils.Streams;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AttackSurfaceAnalyzer.Tests
{
    [TestClass]
    public class AsaAnalyzerTests
    {
        public AsaAnalyzerTests()
        {
        }

        private const string TestPathOne = "TestPath1";

        private readonly FileMonitorObject testPathOneObject = new FileMonitorObject(TestPathOne) { FileSystemObject = new FileSystemObject(TestPathOne) { IsExecutable = true } };

        [ClassInitialize]
        public static void ClassSetup(TestContext _)
        {
            Logger.Setup(false, true);
            Strings.Setup();
            AsaTelemetry.SetEnabled(enabled: false);
        }

        [TestMethod]
        public void VerifyFileMonitorAsFile()
        {
            var RuleName = "AndRule";
            var andRule = new Rule(RuleName)
            {
                Expression = "0 AND 1",
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.EQ)
                    {
                        Label = "0",
                        Data = new List<string>()
                        {
                            "TestPath1"
                        }
                    },
                    new Clause("IsExecutable", OPERATION.IS_TRUE)
                    {
                        Label = "1"
                    }
                }
            };

            var analyzer = GetAnalyzerForRule(andRule);

            var opts = new CompareCommandOptions(null, "SecondRun") { ApplySubObjectRulesToMonitor = true };

            var results = AttackSurfaceAnalyzerClient.AnalyzeMonitored(opts, analyzer, new MonitorObject[] { testPathOneObject });

            Assert.IsTrue(results.Any(x => x.Value.Any(y => y.Identity == testPathOneObject.Identity && y.Rules.Contains(andRule))));

            opts = new CompareCommandOptions(null, "SecondRun") { ApplySubObjectRulesToMonitor = false };

            results = AttackSurfaceAnalyzerClient.AnalyzeMonitored(opts, analyzer, new MonitorObject[] { testPathOneObject });

            Assert.IsFalse(results.Any(x => x.Value.Any(y => y.Identity == testPathOneObject.Identity && y.Rules.Contains(andRule))));
        }

        private Analyzer GetAnalyzerForRule(Rule rule)
        {
            var file = new RuleFile()
            {
                Rules = new List<Rule>()
                {
                    rule
                }
            };

            return new Analyzer(AsaHelpers.GetPlatform(), file);
        }
    }
}
