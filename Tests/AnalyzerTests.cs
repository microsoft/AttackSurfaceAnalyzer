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

        private readonly CompareResult testPathOneObject = new CompareResult()
        {
            Base = new FileSystemObject(TestPathOne)
        };
        private readonly CompareResult testPathTwoObject = new CompareResult()
        {
            Base = new FileSystemObject(TestPathTwo)
        };
        private readonly CompareResult testPathTwoExecutableObject = new CompareResult()
        {
            Base = new FileSystemObject(TestPathTwo)
            {
                IsExecutable = true
            }
        };
        private readonly CompareResult testPathOneExecutableObject = new CompareResult()
        {
            Base = new FileSystemObject(TestPathOne)
            {
                IsExecutable = true
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

            var analyzer = new Analyzer(AsaHelpers.GetPlatform(),file);

            Assert.IsTrue(analyzer.Analyze(testPathOneObject) == ANALYSIS_RESULT_TYPE.FATAL);
            Assert.IsTrue(analyzer.Analyze(testPathTwoObject) == file.DefaultLevels[RESULT_TYPE.FILE]);
            Assert.IsTrue(analyzer.Analyze(testPathOneExecutableObject) == ANALYSIS_RESULT_TYPE.FATAL);
            Assert.IsTrue(analyzer.Analyze(testPathTwoExecutableObject) == ANALYSIS_RESULT_TYPE.FATAL);

            TearDown();
        }

        [TestMethod]
        public void VerifyAnd()
        {
            Setup();

            var andRule = new Rule("AndRule")
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
                    andRule
                }
            };

            var analyzer = new Analyzer(AsaHelpers.GetPlatform(), file);

            Assert.IsTrue(analyzer.Analyze(testPathOneObject) == file.DefaultLevels[RESULT_TYPE.FILE]);
            Assert.IsTrue(analyzer.Analyze(testPathTwoObject) == file.DefaultLevels[RESULT_TYPE.FILE]);
            Assert.IsTrue(analyzer.Analyze(testPathOneExecutableObject) == ANALYSIS_RESULT_TYPE.FATAL);
            Assert.IsTrue(analyzer.Analyze(testPathTwoExecutableObject) == file.DefaultLevels[RESULT_TYPE.FILE]);

            TearDown();
        }

        [TestMethod]
        public void VerifyNand()
        {
            Setup();

            var nandRule = new Rule("NandRule")
            {
                Expression = "0 NAND 1",
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
                    new Clause("IsExecutable", OPERATION.IS_NULL)
                    {
                        Label = "1",
                    }
                }
            };

            var file = new RuleFile()
            {
                Rules = new List<Rule>()
                {
                    nandRule
                }
            };

            var analyzer = new Analyzer(AsaHelpers.GetPlatform(), file);

            Assert.IsTrue(analyzer.Analyze(testPathOneObject) == file.DefaultLevels[RESULT_TYPE.FILE]);
            Assert.IsTrue(analyzer.Analyze(testPathTwoObject) == ANALYSIS_RESULT_TYPE.FATAL);
            Assert.IsTrue(analyzer.Analyze(testPathOneExecutableObject) == ANALYSIS_RESULT_TYPE.FATAL);
            Assert.IsTrue(analyzer.Analyze(testPathTwoExecutableObject) == ANALYSIS_RESULT_TYPE.FATAL);

            TearDown();
        }

        [TestMethod]
        public void VerifyXor()
        {
            Setup();

            var xorRule = new Rule("XorRule")
            {
                Expression = "0 XOR 1",
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.EQ)
                    {
                        Label = "0",
                        Data = new List<string>()
                        {
                            TestPathOne
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
                    xorRule
                }
            };

            var analyzer = new Analyzer(AsaHelpers.GetPlatform(), file);

            Assert.IsTrue(analyzer.Analyze(testPathOneObject) == ANALYSIS_RESULT_TYPE.FATAL);
            Assert.IsTrue(analyzer.Analyze(testPathTwoObject) == file.DefaultLevels[RESULT_TYPE.FILE]);
            Assert.IsTrue(analyzer.Analyze(testPathOneExecutableObject) == file.DefaultLevels[RESULT_TYPE.FILE]);
            Assert.IsTrue(analyzer.Analyze(testPathTwoExecutableObject) == ANALYSIS_RESULT_TYPE.FATAL);


            TearDown();
        }

        [TestMethod]
        public void VerifyNot()
        {
            Setup();

            var notRule = new Rule("NotRule")
            {
                Expression = "NOT 0",
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.EQ)
                    {
                        Label = "0",
                        Data = new List<string>()
                        {
                            TestPathOne
                        }
                    }
                }
            };

            var file = new RuleFile()
            {
                Rules = new List<Rule>()
                {
                    notRule
                }
            };

            var analyzer = new Analyzer(AsaHelpers.GetPlatform(), file);

            Assert.IsTrue(analyzer.Analyze(testPathOneObject) == file.DefaultLevels[RESULT_TYPE.FILE]);
            Assert.IsTrue(analyzer.Analyze(testPathTwoObject) == ANALYSIS_RESULT_TYPE.FATAL);

            TearDown();
        }

        [TestMethod]
        public void VerifyNor()
        {
            Setup();

            var norRule = new Rule("NorRule")
            {
                Expression = "0 NOR 1",
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
                    norRule
                }
            };

            var analyzer = new Analyzer(AsaHelpers.GetPlatform(), file);

            Assert.IsTrue(analyzer.Analyze(testPathOneObject) == file.DefaultLevels[RESULT_TYPE.FILE]);
            Assert.IsTrue(analyzer.Analyze(testPathTwoObject) == ANALYSIS_RESULT_TYPE.FATAL);
            Assert.IsTrue(analyzer.Analyze(testPathOneExecutableObject) == file.DefaultLevels[RESULT_TYPE.FILE]);
            Assert.IsTrue(analyzer.Analyze(testPathTwoExecutableObject) == file.DefaultLevels[RESULT_TYPE.FILE]);

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

            invalidRule = new Rule("InvalidRule6")
            {
                Expression = "1 NOT AND 0",
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

            invalidRule = new Rule("InvalidRule7")
            {
                Expression = "1 AND NOT NOT 0",
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
