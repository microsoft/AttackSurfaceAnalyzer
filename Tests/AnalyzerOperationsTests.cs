// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.Linq;

namespace AttackSurfaceAnalyzer.Tests
{
    [TestClass]
    public class AnalyzerTests
    {
        private const string TestPathOne = "TestPath1";
        private const string TestPathTwo = "TestPath2";

        private readonly CompareResult testPathOneExecutableObject = new CompareResult()
        {
            Base = new FileSystemObject(TestPathOne)
            {
                IsExecutable = true
            }
        };

        private readonly CompareResult testPathOneObject = new CompareResult()
        {
            Base = new FileSystemObject(TestPathOne)
        };

        private readonly CompareResult testPathTwoExecutableObject = new CompareResult()
        {
            Base = new FileSystemObject(TestPathTwo)
            {
                IsExecutable = true
            }
        };

        private readonly CompareResult testPathTwoObject = new CompareResult()
        {
            Base = new FileSystemObject(TestPathTwo)
        };

        [ClassInitialize]
        public static void ClassSetup(TestContext _)
        {
            Logger.Setup(false, true);
            Strings.Setup();
            AsaTelemetry.SetEnabled(enabled:false);
        }

        [TestMethod]
        public void TestXorFromNand()
        {
            var RuleName = "XOR from NAND";
            var norRule = new AsaRule(RuleName)
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

            var analyzer = new Analyzer();
            var ruleList = new List<Rule>() { norRule };

            Assert.IsTrue(analyzer.Analyze(ruleList, testPathOneObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(!analyzer.Analyze(ruleList, testPathTwoObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(!analyzer.Analyze(ruleList, testPathOneExecutableObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(analyzer.Analyze(ruleList, testPathTwoExecutableObject).Any(x => x.Name == RuleName));
        }

        [TestMethod]
        public void VerifyAccessSubproperties()
        {
            var regObj = new CompareResult()
            {
                Base = new RegistryObject("ContainsListObject", Microsoft.Win32.RegistryView.Registry32)
                {
                    Values = new Dictionary<string, string>()
                    {
                        { "One", "Two"}
                    }
                }
            };

            var RuleName = "ContainsRule";
            var containsRule = new AsaRule(RuleName)
            {
                ResultType = RESULT_TYPE.REGISTRY,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Values.One", OPERATION.EQ)
                    {
                        Label = "0",
                        Data = new List<string>()
                        {
                            "Two"
                        }
                    }
                }
            };

            var analyzer = new Analyzer();
            var ruleList = new List<Rule>() { containsRule };
            Assert.IsTrue(analyzer.Analyze(ruleList,regObj).Any(x => x.Name == RuleName));
        }

        [TestMethod]
        public void VerifyAnd()
        {
            var RuleName = "AndRule";
            var andRule = new AsaRule(RuleName)
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

            var analyzer = new Analyzer();
            var ruleList = new List<Rule>() { andRule };

            Assert.IsTrue(!analyzer.Analyze(ruleList, testPathOneObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(!analyzer.Analyze(ruleList, testPathTwoObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(analyzer.Analyze(ruleList, testPathOneExecutableObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(!analyzer.Analyze(ruleList, testPathTwoExecutableObject).Any(x => x.Name == RuleName));
        }

        [TestMethod]
        public void VerifyEmbeddedRulesAreValid()
        {
            var ruleFile = RuleFile.LoadEmbeddedFilters();
            Assert.IsTrue(!Analyzer.VerifyRules(ruleFile.GetRules()).Any());
        }

        [TestMethod]
        public void VerifyInvalidRuleDetection()
        {
            var invalidRule = new AsaRule("Unbalanced Parentheses")
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

            invalidRule = new AsaRule("ClauseInParenthesesLabel")
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

            invalidRule = new AsaRule("CharactersBetweenParentheses")
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

            invalidRule = new AsaRule("CharactersBeforeOpenParentheses")
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

            invalidRule = new AsaRule("CharactersBetweenClosedParentheses")
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

            invalidRule = new AsaRule("CharactersAfterClosedParentheses")
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

            invalidRule = new AsaRule("MultipleConsecutiveNots")
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

            invalidRule = new AsaRule("CloseParenthesesWithNot")
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

            invalidRule = new AsaRule("WhiteSpaceLabel")
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

            invalidRule = new AsaRule("InvalidOperator")
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

            invalidRule = new AsaRule("InvalidNotOperator")
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

            invalidRule = new AsaRule("EndsWithOperator")
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

            invalidRule = new AsaRule("UnusedLabel")
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

            invalidRule = new AsaRule("MissingLabel")
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

            invalidRule = new AsaRule("ExpressionRequiresLabels")
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

            invalidRule = new AsaRule("OutOfOrder")
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

            invalidRule = new AsaRule("StartWithOperator")
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

            invalidRule = new AsaRule("Case Sensitivity")
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

        [TestMethod]
        public void VerifyNand()
        {
            var RuleName = "NandRule";
            var nandRule = new AsaRule(RuleName)
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

            var analyzer = new Analyzer();
            var ruleList = new List<Rule>() { nandRule };

            Assert.IsTrue(!analyzer.Analyze(ruleList, testPathOneObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(analyzer.Analyze(ruleList, testPathTwoObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(analyzer.Analyze(ruleList, testPathOneExecutableObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(analyzer.Analyze(ruleList, testPathTwoExecutableObject).Any(x => x.Name == RuleName));
        }

        [TestMethod]
        public void VerifyNor()
        {
            var RuleName = "NorRule";
            var norRule = new AsaRule(RuleName)
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

            var analyzer = new Analyzer();
            var ruleList = new List<Rule>() { norRule };

            Assert.IsTrue(!analyzer.Analyze(ruleList, testPathOneObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(analyzer.Analyze(ruleList, testPathTwoObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(!analyzer.Analyze(ruleList, testPathOneExecutableObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(!analyzer.Analyze(ruleList, testPathTwoExecutableObject).Any(x => x.Name == RuleName));
        }

        [TestMethod]
        public void VerifyNot()
        {
            var RuleName = "NotRule";
            var notRule = new AsaRule(RuleName)
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

            var analyzer = new Analyzer();
            var ruleList = new List<Rule>() { notRule };

            Assert.IsTrue(!analyzer.Analyze(ruleList, testPathOneObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(analyzer.Analyze(ruleList, testPathTwoObject).Any(x => x.Name == RuleName));
        }

        [TestMethod]
        public void VerifyOr()
        {
            var RuleName = "OrRule";
            var orRule = new AsaRule(RuleName)
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

            var analyzer = new Analyzer();
            var ruleList = new List<Rule>() { orRule };

            Assert.IsTrue(analyzer.Analyze(ruleList, testPathOneObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(!analyzer.Analyze(ruleList, testPathTwoObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(analyzer.Analyze(ruleList, testPathOneExecutableObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(analyzer.Analyze(ruleList, testPathTwoExecutableObject).Any(x => x.Name == RuleName));
        }

        [TestMethod]
        public void VerifyValidRuleDetection()
        {
            var validRule = new AsaRule("Regular Rule")
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

            validRule = new AsaRule("Extraneous Parenthesis")
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

            validRule = new AsaRule("Deeply Nested Expression")
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

            validRule = new AsaRule("StringsForClauseLabels")
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
        public void VerifyXor()
        {
            var RuleName = "XorRule";
            var xorRule = new AsaRule(RuleName)
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

            var analyzer = new Analyzer();
            var ruleList = new List<Rule>() { xorRule };

            Assert.IsTrue(analyzer.Analyze(ruleList, testPathOneObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(!analyzer.Analyze(ruleList, testPathTwoObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(!analyzer.Analyze(ruleList, testPathOneExecutableObject).Any(x => x.Name == RuleName));
            Assert.IsTrue(analyzer.Analyze(ruleList, testPathTwoExecutableObject).Any(x => x.Name == RuleName));
        }

        private bool VerifyRule(Rule rule)
        {
            return !Analyzer.VerifyRules(new List<Rule>() { rule }).Any();
        }
    }
}