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
    public class AnalyzerTests
    {
        private const string TestPathOne = "TestPath1";
        private const string TestPathTwo = "TestPath2";

        private CompareResult testPathOneObject;
        private CompareResult testPathTwoObject;
        private CompareResult testPathOneExecutableObject;
        private CompareResult testPathTwoExecutableObject;

        [TestInitialize]
        public void Setup()
        {
            Logger.Setup(false, true);
            Strings.Setup();
            AsaTelemetry.Setup(test: true);
            DatabaseManager.Setup(Path.GetTempFileName());
            ResetObjects();
        }

        public void ResetObjects()
        {
            testPathOneObject = new CompareResult()
            {
                Base = new FileSystemObject(TestPathOne)
            };
            testPathTwoObject = new CompareResult()
            {
                Base = new FileSystemObject(TestPathTwo)
            };
            testPathOneExecutableObject = new CompareResult()
            {
                Base = new FileSystemObject(TestPathOne)
                {
                    IsExecutable = true
                }
            };
            testPathTwoExecutableObject = new CompareResult()
            {
                Base = new FileSystemObject(TestPathTwo)
                {
                    IsExecutable = true
                }
            };
        }

        [TestCleanup]
        public void TearDown()
        {
            DatabaseManager.Destroy();
        }

        [TestMethod]
        public void VerifyEmbeddedRulesAreValid()
        {
            var analyzer = new Analyzer(AsaHelpers.GetPlatform());
            Assert.IsTrue(!analyzer.VerifyRules().Any());
        }

        [TestMethod]
        public void VerifyOr()
        {
            var RuleName = "OrRule";
            var orRule = new Rule(RuleName)
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

            Assert.IsTrue(analyzer.Analyze(testPathOneObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(!analyzer.Analyze(testPathTwoObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(analyzer.Analyze(testPathOneExecutableObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(analyzer.Analyze(testPathTwoExecutableObject).Any(x => x.Name == RuleName));
        }

        [TestMethod]
        public void VerifyAnd()
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

            Assert.IsTrue(!analyzer.Analyze(testPathOneObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(!analyzer.Analyze(testPathTwoObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(analyzer.Analyze(testPathOneExecutableObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(!analyzer.Analyze(testPathTwoExecutableObject).Any(x => x.Name == RuleName));
        }

        [TestMethod]
        public void VerifyNand()
        {
            var RuleName = "NandRule";
            var nandRule = new Rule(RuleName)
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

            Assert.IsTrue(!analyzer.Analyze(testPathOneObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(analyzer.Analyze(testPathTwoObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(analyzer.Analyze(testPathOneExecutableObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(analyzer.Analyze(testPathTwoExecutableObject).Any(x => x.Name == RuleName));
        }

        [TestMethod]
        public void VerifyXor()
        {
            var RuleName = "XorRule";
            var xorRule = new Rule(RuleName)
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

            Assert.IsTrue(analyzer.Analyze(testPathOneObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(!analyzer.Analyze(testPathTwoObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(!analyzer.Analyze(testPathOneExecutableObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(analyzer.Analyze(testPathTwoExecutableObject).Any(x => x.Name == RuleName));
        }

        [TestMethod]
        public void VerifyNot()
        {
            var RuleName = "NotRule";
            var notRule = new Rule(RuleName)
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

            Assert.IsTrue(!analyzer.Analyze(testPathOneObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(analyzer.Analyze(testPathTwoObject).Any(x => x.Name == RuleName));
        }

        [TestMethod]
        public void VerifyNor()
        {
            var RuleName = "NorRule";
            var norRule = new Rule(RuleName)
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

            Assert.IsTrue(!analyzer.Analyze(testPathOneObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(analyzer.Analyze(testPathTwoObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(!analyzer.Analyze(testPathOneExecutableObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(!analyzer.Analyze(testPathTwoExecutableObject).Any(x => x.Name == RuleName));
        }

        [TestMethod]
        public void TestXorFromNand()
        {
            var RuleName = "XOR from NAND";
            var norRule = new Rule(RuleName)
            {
                Expression = "(0 NAND (0 NAND 1)) NAND (1 NAND (0 NAND 1))",
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

            var analyzer = GetAnalyzerForRule(norRule);

            Assert.IsTrue(analyzer.Analyze(testPathOneObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(!analyzer.Analyze(testPathTwoObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(!analyzer.Analyze(testPathOneExecutableObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(analyzer.Analyze(testPathTwoExecutableObject).Any(x => x.Name == RuleName));
        }

        [TestMethod]
        public void VerifyValidRuleDetection()
        {
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
            var invalidRule = new Rule("Unbalanced Parentheses")
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

            invalidRule = new Rule("ClauseInParenthesesLabel")
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

            invalidRule = new Rule("CharactersBetweenParentheses")
            {
                Expression = "(W(I",
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.IS_NULL)
                    {
                        Label = "W(I"
                    }
                }
            };

            Assert.IsFalse(VerifyRule(invalidRule));

            invalidRule = new Rule("CharactersBeforeOpenParentheses")
            {
                Expression = "W(I",
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.IS_NULL)
                    {
                        Label = "W(I"
                    }
                }
            };

            Assert.IsFalse(VerifyRule(invalidRule));

            invalidRule = new Rule("CharactersBetweenClosedParentheses")
            {
                Expression = "(0 AND W)I)",
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.IS_NULL)
                    {
                        Label = "W)I"
                    },
                    new Clause("Path", OPERATION.IS_NULL)
                    {
                        Label = "0"
                    }
                }
            };

            Assert.IsFalse(VerifyRule(invalidRule));

            invalidRule = new Rule("CharactersAfterClosedParentheses")
            {
                Expression = "0 AND W)I",
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.IS_NULL)
                    {
                        Label = "W)I"
                    },
                    new Clause("Path", OPERATION.IS_NULL)
                    {
                        Label = "0"
                    }
                }
            };

            Assert.IsFalse(VerifyRule(invalidRule));

            invalidRule = new Rule("MultipleConsecutiveNots")
            {
                Expression = "0 AND NOT NOT 1",
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.IS_NULL)
                    {
                        Label = "1"
                    },
                    new Clause("Path", OPERATION.IS_NULL)
                    {
                        Label = "0"
                    }
                }
            };

            Assert.IsFalse(VerifyRule(invalidRule));

            invalidRule = new Rule("CloseParenthesesWithNot")
            {
                Expression = "(0 AND NOT) 1",
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.IS_NULL)
                    {
                        Label = "1"
                    },
                    new Clause("Path", OPERATION.IS_NULL)
                    {
                        Label = "0"
                    }
                }
            };

            Assert.IsFalse(VerifyRule(invalidRule));

            invalidRule = new Rule("WhiteSpaceLabel")
            {
                Expression = "0 AND   ",
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

            invalidRule = new Rule("InvalidOperator")
            {
                Expression = "0 XAND 1",
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.IS_NULL)
                    {
                        Label = "1"
                    },
                    new Clause("Path", OPERATION.IS_NULL)
                    {
                        Label = "0"
                    }
                }
            };

            Assert.IsFalse(VerifyRule(invalidRule));

            invalidRule = new Rule("InvalidNotOperator")
            {
                Expression = "0 NOT AND 1",
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.IS_NULL)
                    {
                        Label = "1"
                    },
                    new Clause("Path", OPERATION.IS_NULL)
                    {
                        Label = "0"
                    }
                }
            };

            Assert.IsFalse(VerifyRule(invalidRule));

            invalidRule = new Rule("EndsWithOperator")
            {
                Expression = "0 AND",
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

            invalidRule = new Rule("UnusedLabel")
            {
                Expression = "0",
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.IS_NULL)
                    {
                        Label = "1"
                    },
                    new Clause("Path", OPERATION.IS_NULL)
                    {
                        Label = "0"
                    }
                }
            };

            Assert.IsFalse(VerifyRule(invalidRule));

            invalidRule = new Rule("MissingLabel")
            {
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.IS_NULL)
                    {
                        Label = "0"
                    },
                    new Clause("Path", OPERATION.IS_NULL)
                }
            };

            Assert.IsFalse(VerifyRule(invalidRule));

            invalidRule = new Rule("ExpressionRequiresLabels")
            {
                Expression = "0 AND 1",
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.IS_NULL),
                    new Clause("Path", OPERATION.IS_NULL)
                }
            };

            Assert.IsFalse(VerifyRule(invalidRule));

            invalidRule = new Rule("OutOfOrder")
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
                    new Clause("IsExecutable", OPERATION.IS_TRUE)
                    {
                        Label = "1"
                    }
                }
            };

            Assert.IsFalse(VerifyRule(invalidRule));

            invalidRule = new Rule("StartWithOperator")
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
        }

        private bool VerifyRule(Rule rule)
        {
            var analyzer = GetAnalyzerForRule(rule);
            return !analyzer.VerifyRules().Any();
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
