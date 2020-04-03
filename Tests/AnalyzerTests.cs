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
                    new Clause("IsExecutable", OPERATION.IS_TRUE)
                    {
                        Label = "1"
                    }
                }
            };

            var analyzer = GetAnalyzerForRule(orRule);

            Assert.IsTrue(analyzer.Analyze(testPathOneObject) == ANALYSIS_RESULT_TYPE.FATAL);
            Assert.IsTrue(analyzer.Analyze(testPathTwoObject) == analyzer.DefaultLevels[RESULT_TYPE.FILE]);
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
                    new Clause("IsExecutable", OPERATION.IS_TRUE)
                    {
                        Label = "1"
                    }
                }
            };

            var analyzer = GetAnalyzerForRule(andRule);

            Assert.IsTrue(analyzer.Analyze(testPathOneObject) == analyzer.DefaultLevels[RESULT_TYPE.FILE]);
            Assert.IsTrue(analyzer.Analyze(testPathTwoObject) == analyzer.DefaultLevels[RESULT_TYPE.FILE]);
            Assert.IsTrue(analyzer.Analyze(testPathOneExecutableObject) == ANALYSIS_RESULT_TYPE.FATAL);
            Assert.IsTrue(analyzer.Analyze(testPathTwoExecutableObject) == analyzer.DefaultLevels[RESULT_TYPE.FILE]);

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

            var analyzer = GetAnalyzerForRule(nandRule);

            Assert.IsTrue(analyzer.Analyze(testPathOneObject) == analyzer.DefaultLevels[RESULT_TYPE.FILE]);
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
                    new Clause("IsExecutable", OPERATION.IS_TRUE)
                    {
                        Label = "1"
                    }
                }
            };

            var analyzer = GetAnalyzerForRule(xorRule);

            Assert.IsTrue(analyzer.Analyze(testPathOneObject) == ANALYSIS_RESULT_TYPE.FATAL);
            Assert.IsTrue(analyzer.Analyze(testPathTwoObject) == analyzer.DefaultLevels[RESULT_TYPE.FILE]);
            Assert.IsTrue(analyzer.Analyze(testPathOneExecutableObject) == analyzer.DefaultLevels[RESULT_TYPE.FILE]);
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

            var analyzer = GetAnalyzerForRule(notRule);

            Assert.IsTrue(analyzer.Analyze(testPathOneObject) == analyzer.DefaultLevels[RESULT_TYPE.FILE]);
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

            var analyzer = GetAnalyzerForRule(norRule);

            Assert.IsTrue(analyzer.Analyze(testPathOneObject) == analyzer.DefaultLevels[RESULT_TYPE.FILE]);
            Assert.IsTrue(analyzer.Analyze(testPathTwoObject) == ANALYSIS_RESULT_TYPE.FATAL);
            Assert.IsTrue(analyzer.Analyze(testPathOneExecutableObject) == analyzer.DefaultLevels[RESULT_TYPE.FILE]);
            Assert.IsTrue(analyzer.Analyze(testPathTwoExecutableObject) == analyzer.DefaultLevels[RESULT_TYPE.FILE]);

            TearDown();
        }

        [TestMethod]
        public void VerifyValidRuleDetection()
        {
            Setup();

            var validRule = new Rule("Regular Rule")
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

            Assert.IsTrue(VerifyRule(validRule));

            validRule = new Rule("Extraneous Parenthesis")
            {
                Expression = "(0 AND 1)",
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

            Assert.IsTrue(VerifyRule(validRule));

            validRule = new Rule("Deeply Nested Expression")
            {
                Expression = "(0 AND 1) OR (2 XOR (3 AND (4 NAND 5)) OR 6)",
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
                    },
                    new Clause("IsExecutable", OPERATION.IS_NULL)
                    {
                        Label = "2"
                    },
                    new Clause("IsExecutable", OPERATION.IS_NULL)
                    {
                        Label = "3"
                    },
                    new Clause("IsExecutable", OPERATION.IS_NULL)
                    {
                        Label = "4"
                    },
                    new Clause("IsExecutable", OPERATION.IS_NULL)
                    {
                        Label = "5"
                    },
                    new Clause("IsExecutable", OPERATION.IS_NULL)
                    {
                        Label = "6"
                    }
                }
            };

            Assert.IsTrue(VerifyRule(validRule));

            validRule = new Rule("StringsForClauseLabels")
            {
                Expression = "FOO AND BAR OR BA$_*",
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("IsExecutable", OPERATION.IS_NULL)
                    {
                        Label = "FOO"
                    },
                    new Clause("IsExecutable", OPERATION.IS_NULL)
                    {
                        Label = "BAR"
                    },
                    new Clause("IsExecutable", OPERATION.IS_NULL)
                    {
                        Label = "BA$_*"
                    }
                }
            };

            Assert.IsTrue(VerifyRule(validRule));
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

            Assert.IsFalse(VerifyRule(invalidRule));

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

            Assert.IsFalse(VerifyRule(invalidRule));

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

            Assert.IsFalse(VerifyRule(invalidRule));

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

            Assert.IsFalse(VerifyRule(invalidRule));

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

            Assert.IsFalse(VerifyRule(invalidRule));

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

            Assert.IsFalse(VerifyRule(invalidRule));

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

            Assert.IsFalse(VerifyRule(invalidRule));

            invalidRule = new Rule("InvalidClauseName")
            {
                Expression = "WITH A SPACE",
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.IS_NULL)
                    {
                        Label = "WITH A SPACE"
                    }
                }
            };

            Assert.IsFalse(VerifyRule(invalidRule));

            invalidRule = new Rule("InvalidClauseName2")
            {
                Expression = "WITH(PARENTHESIS)",
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.IS_NULL)
                    {
                        Label = "WITH(PARENTHESIS)"
                    }
                }
            };

            Assert.IsFalse(VerifyRule(invalidRule));

            invalidRule = new Rule("ExtraClause")
            {
                Expression = "FIRSTCLAUSE",
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.IS_NULL)
                    {
                        Label = "FIRSTCLAUSE"
                    },
                    new Clause("IsExecutable", OPERATION.IS_NULL)
                    {
                        Label = "EXTRACLAUSE"
                    }
                }
            };

            Assert.IsFalse(VerifyRule(invalidRule));

            invalidRule = new Rule("Incomplete Expression")
            {
                Expression = "0 OR",
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.IS_NULL)
                    {
                        Label = "0"
                    }
                }
            };

            Assert.IsFalse(VerifyRule(invalidRule));

            invalidRule = new Rule("Trailing Not")
            {
                Expression = "0 OR NOT",
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.IS_NULL)
                    {
                        Label = "0"
                    }
                }
            };

            Assert.IsFalse(VerifyRule(invalidRule));

            invalidRule = new Rule("Incomplete Subexpression")
            {
                Expression = "0 OR (1 OR) 0",
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.IS_NULL)
                    {
                        Label = "0"
                    },
                    new Clause("Path", OPERATION.IS_NULL)
                    {
                        Label = "1"
                    }
                }
            };

            Assert.IsFalse(VerifyRule(invalidRule));

            invalidRule = new Rule("Case Sensitivity")
            {
                Expression = "Variable",
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.IS_NULL)
                    {
                        Label = "VARIABLE"
                    }
                }
            };

            Assert.IsFalse(VerifyRule(invalidRule));

            TearDown();
        }

        private bool VerifyRule(Rule rule)
        {
            var analyzer = GetAnalyzerForRule(rule);
            return analyzer.VerifyRules();
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
