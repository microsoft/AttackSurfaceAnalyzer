using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace AttackSurfaceAnalyzer.Tests
{
    [TestClass]
    public class AnalyzerOperationsTests
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
        public void VerifyEqOperation()
        {
            Setup();

            var assertTrueObject = new CompareResult()
            {
                Base = new FileSystemObject("TestPath")
                {
                    IsDirectory = true,
                    Size = 700
                }
            };

            var assertFalseObject = new CompareResult()
            {
                Base = new FileSystemObject("TestPath2")
                {
                    IsDirectory = false,
                    Size = 701
                }
            };

            var stringEquals = new Rule("String Equals Rule")
            {
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.EQ)
                    {
                        Data = new List<string>()
                        {
                            "TestPath"
                        }
                    }
                }
            };

            var boolEquals = new Rule("Bool Equals Rule")
            {
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("IsDirectory", OPERATION.EQ)
                    {
                        Data = new List<string>()
                        {
                            "True"
                        }
                    }
                }
            };

            var intEquals = new Rule("Int Equals Rule")
            {
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Size", OPERATION.EQ)
                    {
                        Data = new List<string>()
                        {
                            "700"
                        }
                    }
                }
            };

            var boolAnalyzer = GetAnalyzerForRule(boolEquals);
            var intAnalyzer = GetAnalyzerForRule(intEquals);
            var stringAnalyzer = GetAnalyzerForRule(stringEquals);

            Assert.IsTrue(boolAnalyzer.Analyze(assertTrueObject).Any(x => x.Name == "Bool Equals Rule"));
            Assert.IsTrue(intAnalyzer.Analyze(assertTrueObject).Any(x => x.Name == "Int Equals Rule"));
            Assert.IsTrue(stringAnalyzer.Analyze(assertTrueObject).Any(x => x.Name == "String Equals Rule"));

            Assert.IsFalse(boolAnalyzer.Analyze(assertFalseObject).Any(x => x.Name == "Bool Equals Rule"));
            Assert.IsFalse(intAnalyzer.Analyze(assertFalseObject).Any(x => x.Name == "Int Equals Rule"));
            Assert.IsFalse(stringAnalyzer.Analyze(assertFalseObject).Any(x => x.Name == "String Equals Rule"));

            TearDown();
        }

        [TestMethod]
        public void VerifyNeqOperation()
        {
            Setup();

            var assertTrueObject = new CompareResult()
            {
                Base = new FileSystemObject("TestPath")
                {
                    IsDirectory = true,
                    Size = 700
                }
            };

            var assertFalseObject = new CompareResult()
            {
                Base = new FileSystemObject("TestPath2")
                {
                    IsDirectory = false,
                    Size = 701
                }
            };

            var stringEquals = new Rule("String Equals Rule")
            {
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.NEQ)
                    {
                        Data = new List<string>()
                        {
                            "TestPath"
                        }
                    }
                }
            };

            var boolEquals = new Rule("Bool Equals Rule")
            {
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("IsDirectory", OPERATION.NEQ)
                    {
                        Data = new List<string>()
                        {
                            "True"
                        }
                    }
                }
            };

            var intEquals = new Rule("Int Equals Rule")
            {
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Size", OPERATION.NEQ)
                    {
                        Data = new List<string>()
                        {
                            "700"
                        }
                    }
                }
            };

            var boolAnalyzer = GetAnalyzerForRule(boolEquals);
            var intAnalyzer = GetAnalyzerForRule(intEquals);
            var stringAnalyzer = GetAnalyzerForRule(stringEquals);

            Assert.IsFalse(boolAnalyzer.Analyze(assertTrueObject).Any(x => x.Name == "Bool Equals Rule"));
            Assert.IsFalse(intAnalyzer.Analyze(assertTrueObject).Any(x => x.Name == "Int Equals Rule"));
            Assert.IsFalse(stringAnalyzer.Analyze(assertTrueObject).Any(x => x.Name == "String Equals Rule"));

            Assert.IsTrue(boolAnalyzer.Analyze(assertFalseObject).Any(x => x.Name == "Bool Equals Rule"));
            Assert.IsTrue(intAnalyzer.Analyze(assertFalseObject).Any(x => x.Name == "Int Equals Rule"));
            Assert.IsTrue(stringAnalyzer.Analyze(assertFalseObject).Any(x => x.Name == "String Equals Rule"));

            TearDown();
        }

        [TestMethod]
        public void VerifyContainsOperation()
        {
            var trueStringObject = new CompareResult()
            {
                Base = new FileSystemObject("ContainsStringObject")
            };

            var falseStringObject = new CompareResult()
            {
                Base = new FileSystemObject("StringObject")
            };

            var superFalseStringObject = new CompareResult()
            {
                Base = new FileSystemObject("NothingInCommon")
            };

            var stringContains = new Rule("String Contains Rule")
            {
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.CONTAINS)
                    {
                        Data = new List<string>()
                        {
                            "Contains",
                            "String",
                            "Object"
                        }
                    }
                }
            };

            var stringAnalyzer = GetAnalyzerForRule(stringContains);

            Assert.IsTrue(stringAnalyzer.Analyze(trueStringObject).Any());
            Assert.IsFalse(stringAnalyzer.Analyze(falseStringObject).Any());
            Assert.IsFalse(stringAnalyzer.Analyze(superFalseStringObject).Any());

            var trueListObject = new CompareResult()
            {
                Base = new RegistryObject("ContainsListObject", Microsoft.Win32.RegistryView.Registry32)
                {
                    Subkeys = new List<string>()
                    {
                        "One",
                        "Two",
                        "Three"
                    }
                }
            };

            var falseListObject = new CompareResult()
            {
                Base = new RegistryObject("ContainsListObject", Microsoft.Win32.RegistryView.Registry32)
                {
                    Subkeys = new List<string>()
                    {
                        "One",
                        "Two",
                    }
                }
            };

            var superFalseListObject = new CompareResult()
            {
                Base = new RegistryObject("ContainsListObject", Microsoft.Win32.RegistryView.Registry32)
            };

            var listContains = new Rule("List Contains Rule")
            {
                ResultType = RESULT_TYPE.REGISTRY,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("SubKeys", OPERATION.CONTAINS)
                    {
                        Data = new List<string>()
                        {
                            "One",
                            "Two",
                            "Three"
                        }
                    }
                }
            };

            var listAnalyzer = GetAnalyzerForRule(listContains);

            Assert.IsTrue(listAnalyzer.Analyze(trueListObject).Any());
            Assert.IsFalse(listAnalyzer.Analyze(falseListObject).Any());
            Assert.IsFalse(listAnalyzer.Analyze(superFalseListObject).Any());

            var trueStringDictObject = new CompareResult()
            {
                Base = new RegistryObject("ContainsStringDictObject", Microsoft.Win32.RegistryView.Registry32)
                {
                    Values = new Dictionary<string, string>()
                    {
                        { "One", "One" },
                        { "Two", "Two" },
                        { "Three", "Three" }
                    }
                }
            };

            var falseStringDictObject = new CompareResult()
            {
                Base = new RegistryObject("ContainsStringDictObject", Microsoft.Win32.RegistryView.Registry32)
                {
                    Values = new Dictionary<string, string>()
                    {
                        { "One", "One" },
                        { "Two", "Three" },
                    }
                }
            };

            var superFalseStringDictObject = new CompareResult()
            {
                Base = new RegistryObject("ContainsStringDictObject", Microsoft.Win32.RegistryView.Registry32)
                {
                    Values = new Dictionary<string, string>()
                    {
                        { "One", "Two" },
                        { "Three", "Four" },
                    }
                }
            };

            var stringDictContains = new Rule("String Dict Contains Rule")
            {
                ResultType = RESULT_TYPE.REGISTRY,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Values", OPERATION.CONTAINS)
                    {
                        DictData = new List<KeyValuePair<string, string>>()
                        {
                            new KeyValuePair<string, string>("One","One"),
                            new KeyValuePair<string, string>("Two","Two"),
                            new KeyValuePair<string, string>("Three","Three")
                        }
                    }
                }
            };

            var stringDictAnalyzer = GetAnalyzerForRule(stringDictContains);

            Assert.IsTrue(stringDictAnalyzer.Analyze(trueStringDictObject).Any());
            Assert.IsFalse(stringDictAnalyzer.Analyze(falseStringDictObject).Any());
            Assert.IsFalse(stringDictAnalyzer.Analyze(superFalseStringDictObject).Any());
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
