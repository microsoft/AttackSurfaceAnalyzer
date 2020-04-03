using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.CodeAnalysis;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.IO;

namespace AttackSurfaceAnalyzer.Tests
{
    [TestClass]
    public class AnalyzerTests
    {
        private const string TestPathOne = "TestPath1";
        private const string TestPathTwo = "TestPath2";
        private const string TestPathThree = "TestPath3";

        private readonly CompareResult testPathOneObject = new CompareResult()
        {
            Base = new FileSystemObject(TestPathOne)
        };
        private readonly CompareResult testPathTwoObject = new CompareResult()
        {
            Base = new FileSystemObject(TestPathTwo)
            {
                IsExecutable = true
            }
        };
        private readonly CompareResult testPathThreeObject = new CompareResult()
        {
            Base = new FileSystemObject(TestPathThree)
            {
                IsDirectory = true
            }
        };

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

            var analyzer = new Analyzer(AsaHelpers.GetPlatform());
            Assert.IsTrue(analyzer.VerifyRules());

            TearDown();
        }

        [TestMethod]
        public void VerifyOr()
        {
            Setup();

            var orRule = new Rule("OrRule")
            {
                Expression = "0 OR 1",
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
                    new Clause("Path", OPERATION.EQ)
                    {
                        Label = "1",
                        Data = new List<string>()
                        {
                            "TestPath2"
                        }
                    }
                }
            };

            var file = new RuleFile()
            {
                Rules = new List<Rule>()
                {
                    orRule
                }
            };

            var analyzer = new Analyzer(AsaHelpers.GetPlatform(),file);

            Assert.IsTrue(analyzer.Analyze(testPathOneObject) == ANALYSIS_RESULT_TYPE.FATAL);
            Assert.IsTrue(analyzer.Analyze(testPathTwoObject) == ANALYSIS_RESULT_TYPE.FATAL);
            Assert.IsTrue(analyzer.Analyze(testPathThreeObject) == file.DefaultLevels[RESULT_TYPE.FILE]);

            TearDown();
        }

        [TestMethod]
        public void VerifyAnd()
        {
            Setup();

            var orRule = new Rule("AndRule")
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
                            "TestPath2"
                        }
                    },
                    new Clause("IsExecutable", OPERATION.EQ)
                    {
                        Label = "1",
                        Data = new List<string>()
                        {
                            "True"
                        }
                    }
                }
            };

            var file = new RuleFile()
            {
                Rules = new List<Rule>()
                {
                    orRule
                }
            };

            var analyzer = new Analyzer(AsaHelpers.GetPlatform(), file);

            Assert.IsTrue(analyzer.Analyze(testPathOneObject) == file.DefaultLevels[RESULT_TYPE.FILE]);
            Assert.IsTrue(analyzer.Analyze(testPathTwoObject) == ANALYSIS_RESULT_TYPE.FATAL);
            Assert.IsTrue(analyzer.Analyze(testPathThreeObject) == file.DefaultLevels[RESULT_TYPE.FILE]);

            TearDown();
        }

        [TestMethod]
        public void VerifyInvalidRuleDetection()
        {
            Setup();

            var invalidRule = new Rule("InvalidRule1")
            {
                Expression = "( 0 AND 1",
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.EQ)
                    {
                        Label = "0",
                        Data = new List<string>()
                        {
                            "TestPath2"
                        }
                    },
                    new Clause("IsExecutable", OPERATION.EQ)
                    {
                        Label = "1",
                        Data = new List<string>()
                        {
                            "True"
                        }
                    }
                }
            };

            var file = new RuleFile()
            {
                Rules = new List<Rule>()
                {
                    invalidRule
                }
            };

            var analyzer = new Analyzer(AsaHelpers.GetPlatform(), file);
            Assert.IsFalse(analyzer.VerifyRules());

            invalidRule = new Rule("InvalidRule2")
            {
                Expression = "0 XAND 1",
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.EQ)
                    {
                        Label = "0",
                        Data = new List<string>()
                        {
                            "TestPath2"
                        }
                    },
                    new Clause("IsExecutable", OPERATION.EQ)
                    {
                        Label = "1",
                        Data = new List<string>()
                        {
                            "True"
                        }
                    }
                }
            };

            file = new RuleFile()
            {
                Rules = new List<Rule>()
                {
                    invalidRule
                }
            };

            analyzer = new Analyzer(AsaHelpers.GetPlatform(), file);
            Assert.IsFalse(analyzer.VerifyRules());

            invalidRule = new Rule("InvalidRule3")
            {
                Expression = "0( OR 1)",
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.EQ)
                    {
                        Label = "0",
                        Data = new List<string>()
                        {
                            "TestPath2"
                        }
                    },
                    new Clause("IsExecutable", OPERATION.EQ)
                    {
                        Label = "1",
                        Data = new List<string>()
                        {
                            "True"
                        }
                    }
                }
            };

            file = new RuleFile()
            {
                Rules = new List<Rule>()
                {
                    invalidRule
                }
            };

            analyzer = new Analyzer(AsaHelpers.GetPlatform(), file);
            Assert.IsFalse(analyzer.VerifyRules());

            invalidRule = new Rule("InvalidRule4")
            {
                Expression = "0 1 AND",
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.EQ)
                    {
                        Label = "0",
                        Data = new List<string>()
                        {
                            "TestPath2"
                        }
                    },
                    new Clause("IsExecutable", OPERATION.EQ)
                    {
                        Label = "1",
                        Data = new List<string>()
                        {
                            "True"
                        }
                    }
                }
            };

            file = new RuleFile()
            {
                Rules = new List<Rule>()
                {
                    invalidRule
                }
            };

            analyzer = new Analyzer(AsaHelpers.GetPlatform(), file);
            Assert.IsFalse(analyzer.VerifyRules());

            invalidRule = new Rule("InvalidRule5")
            {
                Expression = "OR 0 1",
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.EQ)
                    {
                        Label = "0",
                        Data = new List<string>()
                        {
                            "TestPath2"
                        }
                    },
                    new Clause("IsExecutable", OPERATION.EQ)
                    {
                        Label = "1",
                        Data = new List<string>()
                        {
                            "True"
                        }
                    }
                }
            };

            file = new RuleFile()
            {
                Rules = new List<Rule>()
                {
                    invalidRule
                }
            };

            analyzer = new Analyzer(AsaHelpers.GetPlatform(), file);
            Assert.IsFalse(analyzer.VerifyRules());

            TearDown();
        }
    }
}
