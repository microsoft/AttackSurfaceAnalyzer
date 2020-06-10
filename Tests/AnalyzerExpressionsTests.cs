// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using Tpm2Lib;
using Signature = AttackSurfaceAnalyzer.Objects.Signature;

namespace AttackSurfaceAnalyzer.Tests
{
    [TestClass]
    public class AnalyzerOperationsTests
    {
        [ClassInitialize]
        public static void ClassSetup(TestContext _)
        {
            Logger.Setup(false, true);
            Strings.Setup();
            AsaTelemetry.Setup(test: true);
        }

        [TestMethod]
        public void VerifyEqOperator()
        {
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
        }

        [TestMethod]
        public void VerifyNeqOperator()
        {
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
        }
        [TestMethod]
        public void VerifyContainsOperator()
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
                    new Clause("Subkeys", OPERATION.CONTAINS)
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

            var trueListDictObject = new CompareResult()
            {
                Base = new RegistryObject("ContainsListDictObject", Microsoft.Win32.RegistryView.Registry32)
                {
                    Permissions = new Dictionary<string, List<string>>()
                    {
                        {
                            "User", new List<string>()
                            {
                                "Read",
                                "Execute"
                            }
                        }
                    }
                }
            };

            var falseListDictObject = new CompareResult()
            {
                Base = new RegistryObject("ContainsListDictObject", Microsoft.Win32.RegistryView.Registry32)
                {
                    Permissions = new Dictionary<string, List<string>>()
                    {
                        {
                            "User", new List<string>()
                            {
                                "Read",
                            }
                        }
                    }
                }
            };

            var alsoFalseListDictObject = new CompareResult()
            {
                Base = new RegistryObject("ContainsListDictObject", Microsoft.Win32.RegistryView.Registry32)
                {
                    Permissions = new Dictionary<string, List<string>>()
                    {
                        {
                            "Contoso", new List<string>()
                            {
                                "Read",
                                "Execute"
                            }
                        }
                    }
                }
            };

            var listDictContains = new Rule("List Dict Contains Rule")
            {
                ResultType = RESULT_TYPE.REGISTRY,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Permissions", OPERATION.CONTAINS)
                    {
                        DictData = new List<KeyValuePair<string, string>>()
                        {
                            new KeyValuePair<string, string>("User","Execute"),
                            new KeyValuePair<string, string>("User","Read"),
                        }
                    }
                }
            };

            var listDictAnalyzer = GetAnalyzerForRule(listDictContains);

            Assert.IsTrue(listDictAnalyzer.Analyze(trueListDictObject).Any());
            Assert.IsFalse(listDictAnalyzer.Analyze(falseListDictObject).Any());
            Assert.IsFalse(listDictAnalyzer.Analyze(alsoFalseListDictObject).Any());
        }

        [TestMethod]
        public void VerifyContainsKeyOperator()
        {
            var trueAlgDict = new CompareResult()
            {
                Base = new TpmObject("TestLocal")
                {
                    PCRs = new Dictionary<(Tpm2Lib.TpmAlgId, uint), byte[]>()
                    {
                        { (TpmAlgId.Sha,1), Array.Empty<byte>() }
                    }
                }
            };

            var falseAlgDict = new CompareResult()
            {
                Base = new TpmObject("TestLocal")
                {
                    PCRs = new Dictionary<(Tpm2Lib.TpmAlgId, uint), byte[]>()
                    {
                        { (TpmAlgId.Sha,15), Array.Empty<byte>() }
                    }
                }
            };

            var algDictContains = new Rule("Alg Dict Changed PCR 1")
            {
                ResultType = RESULT_TYPE.TPM,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("PCRs", OPERATION.CONTAINS_KEY)
                    {
                        Data = new List<string>()
                        {
                            "(Sha, 1)"
                        }
                    }
                }
            };

            var algDictAnalyzer = GetAnalyzerForRule(algDictContains);

            Assert.IsTrue(algDictAnalyzer.Analyze(trueAlgDict).Any());
            Assert.IsFalse(algDictAnalyzer.Analyze(falseAlgDict).Any());
        }

        [TestMethod]
        public void VerifyContainsAnyOperator()
        {
            var trueStringObject = new CompareResult()
            {
                Base = new FileSystemObject("ContainsStringObject")
            };

            var alsoTrueStringObject = new CompareResult()
            {
                Base = new FileSystemObject("StringObject")
            };

            var falseStringObject = new CompareResult()
            {
                Base = new FileSystemObject("NothingInCommon")
            };

            var stringContains = new Rule("String Contains Any Rule")
            {
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.CONTAINS_ANY)
                    {
                        Data = new List<string>()
                        {
                            "String",
                        }
                    }
                }
            };

            var stringAnalyzer = GetAnalyzerForRule(stringContains);

            Assert.IsTrue(stringAnalyzer.Analyze(trueStringObject).Any());
            Assert.IsTrue(stringAnalyzer.Analyze(alsoTrueStringObject).Any());
            Assert.IsFalse(stringAnalyzer.Analyze(falseStringObject).Any());

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

            var alsoTrueListObject = new CompareResult()
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

            var falseListObject = new CompareResult()
            {
                Base = new RegistryObject("ContainsListObject", Microsoft.Win32.RegistryView.Registry32)
            };

            var listContains = new Rule("List Contains Any Rule")
            {
                ResultType = RESULT_TYPE.REGISTRY,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Subkeys", OPERATION.CONTAINS_ANY)
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
            Assert.IsTrue(listAnalyzer.Analyze(alsoTrueListObject).Any());
            Assert.IsFalse(listAnalyzer.Analyze(falseListObject).Any());

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

            var alsoTrueStringDict = new CompareResult()
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

            var stringDictContains = new Rule("String Dict Contains Any Rule")
            {
                ResultType = RESULT_TYPE.REGISTRY,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Values", OPERATION.CONTAINS_ANY)
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
            Assert.IsTrue(stringDictAnalyzer.Analyze(alsoTrueStringDict).Any());
            Assert.IsFalse(stringDictAnalyzer.Analyze(superFalseStringDictObject).Any());

            var trueListDictObject = new CompareResult()
            {
                Base = new RegistryObject("ContainsListDictObject", Microsoft.Win32.RegistryView.Registry32)
                {
                    Permissions = new Dictionary<string, List<string>>()
                    {
                        {
                            "User", new List<string>()
                            {
                                "Read",
                                "Execute"
                            }
                        }
                    }
                }
            };

            var alsoTrueListDictObject = new CompareResult()
            {
                Base = new RegistryObject("ContainsListDictObject", Microsoft.Win32.RegistryView.Registry32)
                {
                    Permissions = new Dictionary<string, List<string>>()
                    {
                        {
                            "User", new List<string>()
                            {
                                "Read",
                            }
                        }
                    }
                }
            };

            var falseListDictObject = new CompareResult()
            {
                Base = new RegistryObject("ContainsListDictObject", Microsoft.Win32.RegistryView.Registry32)
                {
                    Permissions = new Dictionary<string, List<string>>()
                    {
                        {
                            "Taco", new List<string>()
                            {
                                "Read",
                                "Execute"
                            }
                        }
                    }
                }
            };

            var listDictContains = new Rule("List Dict Contains Any Rule")
            {
                ResultType = RESULT_TYPE.REGISTRY,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Permissions", OPERATION.CONTAINS_ANY)
                    {
                        DictData = new List<KeyValuePair<string, string>>()
                        {
                            new KeyValuePair<string, string>("User","Execute"),
                            new KeyValuePair<string, string>("User","Read")
                        }
                    }
                }
            };

            var listDictAnalyzer = GetAnalyzerForRule(listDictContains);

            Assert.IsTrue(listDictAnalyzer.Analyze(trueListDictObject).Any());
            Assert.IsTrue(listDictAnalyzer.Analyze(alsoTrueListDictObject).Any());
            Assert.IsFalse(listDictAnalyzer.Analyze(falseListDictObject).Any());
        }

        [TestMethod]
        public void VerifyGtOperator()
        {
            var trueGtObject = new CompareResult()
            {
                Base = new OpenPortObject(1025, TRANSPORT.TCP, ADDRESS_FAMILY.InterNetwork)
            };
            var falseGtObject = new CompareResult()
            {
                Base = new OpenPortObject(1023, TRANSPORT.TCP, ADDRESS_FAMILY.InterNetwork)
            };

            var gtRule = new Rule("Gt Rule")
            {
                ResultType = RESULT_TYPE.PORT,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Port", OPERATION.GT)
                    {
                        Data = new List<string>()
                        {
                            "1024"
                        }
                    }
                }
            };

            var badGtRule = new Rule("Bad Gt Rule")
            {
                ResultType = RESULT_TYPE.PORT,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Port", OPERATION.GT)
                    {
                        Data = new List<string>()
                        {
                            "CONTOSO"
                        }
                    }
                }
            };

            var gtAnalyzer = GetAnalyzerForRule(gtRule);

            Assert.IsTrue(gtAnalyzer.Analyze(trueGtObject).Any());
            Assert.IsFalse(gtAnalyzer.Analyze(falseGtObject).Any());

            var badGtAnalyzer = GetAnalyzerForRule(badGtRule);

            Assert.IsFalse(badGtAnalyzer.Analyze(trueGtObject).Any());
            Assert.IsFalse(badGtAnalyzer.Analyze(falseGtObject).Any());
        }

        [TestMethod]
        public void VerifyLtOperator()
        {
            var falseLtObject = new CompareResult()
            {
                Base = new OpenPortObject(1025, TRANSPORT.TCP, ADDRESS_FAMILY.InterNetwork)
            };
            var trueLtObject = new CompareResult()
            {
                Base = new OpenPortObject(1023, TRANSPORT.TCP, ADDRESS_FAMILY.InterNetwork)
            };

            var ltRule = new Rule("Lt Rule")
            {
                ResultType = RESULT_TYPE.PORT,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Port", OPERATION.LT)
                    {
                        Data = new List<string>()
                        {
                            "1024"
                        }
                    }
                }
            };

            var ltAnalyzer = GetAnalyzerForRule(ltRule);

            Assert.IsTrue(ltAnalyzer.Analyze(trueLtObject).Any());
            Assert.IsFalse(ltAnalyzer.Analyze(falseLtObject).Any());

            var badLtRule = new Rule("Bad Lt Rule")
            {
                ResultType = RESULT_TYPE.PORT,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Port", OPERATION.GT)
                    {
                        Data = new List<string>()
                        {
                            "CONTOSO"
                        }
                    }
                }
            };

            var badLtAnalyzer = GetAnalyzerForRule(badLtRule);

            Assert.IsFalse(badLtAnalyzer.Analyze(trueLtObject).Any());
            Assert.IsFalse(badLtAnalyzer.Analyze(falseLtObject).Any());
        }

        [TestMethod]
        public void VerifyRegexOperator()
        {
            var falseRegexObject = new CompareResult()
            {
                Base = new FileSystemObject("TestPathHere")
            };
            var trueRegexObject = new CompareResult()
            {
                Base = new FileSystemObject("Directory/File")
            };

            var regexRule = new Rule("Regex Rule")
            {
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.REGEX)
                    {
                        Data = new List<string>()
                        {
                            ".+\\/.+"
                        }
                    }
                }
            };

            var regexAnalyzer = GetAnalyzerForRule(regexRule);

            Assert.IsTrue(regexAnalyzer.Analyze(trueRegexObject).Any());
            Assert.IsFalse(regexAnalyzer.Analyze(falseRegexObject).Any());
        }

        [TestMethod]
        public void VerifyWasModifiedOperator()
        {
            var falseModifiedObject = new CompareResult()
            {
                Base = new FileSystemObject("TestPathHere")
            };

            var alsoFalseModifiedObject = new CompareResult()
            {
                Base = new FileSystemObject("TestPathHere"),
                Compare = new FileSystemObject("TestPathHere")
                {
                    IsDirectory = true
                }
            };

            var trueModifiedObject = new CompareResult()
            {
                Base = new FileSystemObject("Directory/File")
                {
                    IsExecutable = true
                },
                Compare = new FileSystemObject("Directory/File")
            };

            var wasModifiedRule = new Rule("Was Modified Rule")
            {
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("IsExecutable", OPERATION.WAS_MODIFIED)
                }
            };

            var regexAnalyzer = GetAnalyzerForRule(wasModifiedRule);

            Assert.IsTrue(regexAnalyzer.Analyze(trueModifiedObject).Any());
            Assert.IsFalse(regexAnalyzer.Analyze(falseModifiedObject).Any());
            Assert.IsFalse(regexAnalyzer.Analyze(alsoFalseModifiedObject).Any());
        }

        [TestMethod]
        public void VerifyEndsWithOperator()
        {
            var trueEndsWithObject = new CompareResult()
            {
                Base = new FileSystemObject("App.exe")
            };
            var falseEndsWithObject = new CompareResult()
            {
                Base = new FileSystemObject("App.pdf")
            };

            var endsWithRule = new Rule("Ends With Rule")
            {
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.ENDS_WITH)
                    {
                        Data = new List<string>()
                        {
                            ".exe"
                        }
                    }
                }
            };

            var endsWithAnalyzer = GetAnalyzerForRule(endsWithRule);

            Assert.IsTrue(endsWithAnalyzer.Analyze(trueEndsWithObject).Any());
            Assert.IsFalse(endsWithAnalyzer.Analyze(falseEndsWithObject).Any());
        }

        [TestMethod]
        public void VerifyStartsWithOperator()
        {
            var trueEndsWithObject = new CompareResult()
            {
                Base = new FileSystemObject("App.exe")
            };
            var falseEndsWithObject = new CompareResult()
            {
                Base = new FileSystemObject("NotAnApp.pdf")
            };

            var endsWithRule = new Rule("Ends With Rule")
            {
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("Path", OPERATION.STARTS_WITH)
                    {
                        Data = new List<string>()
                        {
                            "App"
                        }
                    }
                }
            };

            var endsWithAnalyzer = GetAnalyzerForRule(endsWithRule);

            Assert.IsTrue(endsWithAnalyzer.Analyze(trueEndsWithObject).Any());
            Assert.IsFalse(endsWithAnalyzer.Analyze(falseEndsWithObject).Any());
        }

        [TestMethod]
        public void VerifyIsNullOperator()
        {
            var falseIsNullObject = new CompareResult()
            {
                Base = new FileSystemObject("App.exe")
                {
                    ContentHash = "HASH"
                }
            };
            var trueIsNullObject = new CompareResult()
            {
                Base = new FileSystemObject("NotAnApp.pdf")
            };

            var isNullRule = new Rule("Is Null Rule")
            {
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("ContentHash", OPERATION.IS_NULL)
                }
            };

            var isNullAnalyzer = GetAnalyzerForRule(isNullRule);

            Assert.IsTrue(isNullAnalyzer.Analyze(trueIsNullObject).Any());
            Assert.IsFalse(isNullAnalyzer.Analyze(falseIsNullObject).Any());
        }

        [TestMethod]
        public void VerifyIsTrueOperator()
        {
            var trueIsTrueObject = new CompareResult()
            {
                Base = new FileSystemObject("App.exe")
                {
                    IsExecutable = true
                }
            };
            var falseIsTrueObject = new CompareResult()
            {
                Base = new FileSystemObject("NotAnApp.pdf")
            };

            var isTrueRule = new Rule("Is True Rule")
            {
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("IsExecutable", OPERATION.IS_TRUE)
                }
            };

            var isTrueAnalyzer = GetAnalyzerForRule(isTrueRule);

            Assert.IsTrue(isTrueAnalyzer.Analyze(trueIsTrueObject).Any());
            Assert.IsFalse(isTrueAnalyzer.Analyze(falseIsTrueObject).Any());
        }

        [TestMethod]
        public void VerifyIsBeforeOperator()
        {
            var trueIsBeforeObject = new CompareResult()
            {
                Base = new FileSystemObject("App.exe")
                {
                    SignatureStatus = new Signature(true)
                    {
                        SigningCertificate = new SerializableCertificate(Thumbprint: string.Empty, Subject: string.Empty, PublicKey: string.Empty, NotAfter: DateTime.Now, NotBefore: DateTime.Now, Issuer: string.Empty, SerialNumber: string.Empty, CertHashString: string.Empty, Pkcs7: string.Empty)
                    }
                }
            };

            var falseIsBeforeObject = new CompareResult()
            {
                Base = new FileSystemObject("App.exe")
                {
                    SignatureStatus = new Signature(true)
                    {
                        SigningCertificate = new SerializableCertificate(Thumbprint: string.Empty, Subject: string.Empty, PublicKey: string.Empty, NotAfter: DateTime.Now.AddYears(1), NotBefore: DateTime.Now, Issuer: string.Empty, SerialNumber: string.Empty, CertHashString: string.Empty, Pkcs7: string.Empty)
                    }
                }
            };

            var isBeforeRule = new Rule("Is Before Rule")
            {
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("SignatureStatus.SigningCertificate.NotAfter", OPERATION.IS_BEFORE)
                    {
                        Data = new List<string>()
                        {
                            DateTime.Now.AddDays(1).ToString()
                        }
                    }
                }
            };

            var isBeforeAnalyzer = GetAnalyzerForRule(isBeforeRule);

            Assert.IsTrue(isBeforeAnalyzer.Analyze(trueIsBeforeObject).Any());
            Assert.IsFalse(isBeforeAnalyzer.Analyze(falseIsBeforeObject).Any());

            var isBeforeShortRule = new Rule("Is Before Short Rule")
            {
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("SignatureStatus.SigningCertificate.NotAfter", OPERATION.IS_BEFORE)
                    {
                        Data = new List<string>()
                        {
                            DateTime.Now.AddDays(1).ToShortDateString()
                        }
                    }
                }
            };

            var isBeforeShortAnalyzer = GetAnalyzerForRule(isBeforeShortRule);

            Assert.IsTrue(isBeforeShortAnalyzer.Analyze(trueIsBeforeObject).Any());
            Assert.IsFalse(isBeforeShortAnalyzer.Analyze(falseIsBeforeObject).Any());
        }

        [TestMethod]
        public void VerifyIsAfterOperator()
        {
            var falseIsAfterObject = new CompareResult()
            {
                Base = new FileSystemObject("App.exe")
                {
                    SignatureStatus = new Signature(true)
                    {
                        SigningCertificate = new SerializableCertificate(Thumbprint: string.Empty, Subject: string.Empty, PublicKey: string.Empty, NotAfter: DateTime.Now, NotBefore: DateTime.Now, Issuer: string.Empty, SerialNumber: string.Empty, CertHashString: string.Empty, Pkcs7: string.Empty)
                    }
                }
            };

            var trueIsAfterObject = new CompareResult()
            {
                Base = new FileSystemObject("App.exe")
                {
                    SignatureStatus = new Signature(true)
                    {
                        SigningCertificate = new SerializableCertificate(Thumbprint: string.Empty, Subject: string.Empty, PublicKey: string.Empty, NotAfter: DateTime.Now.AddYears(1), NotBefore: DateTime.Now, Issuer: string.Empty, SerialNumber: string.Empty, CertHashString: string.Empty, Pkcs7: string.Empty)
                    }
                }
            };

            var isAfterRule = new Rule("Is After Rule")
            {
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("SignatureStatus.SigningCertificate.NotAfter", OPERATION.IS_AFTER)
                    {
                        Data = new List<string>()
                        {
                            DateTime.Now.AddDays(1).ToString()
                        }
                    }
                }
            };

            var isAfterAnalyzer = GetAnalyzerForRule(isAfterRule);

            Assert.IsTrue(isAfterAnalyzer.Analyze(trueIsAfterObject).Any());
            Assert.IsFalse(isAfterAnalyzer.Analyze(falseIsAfterObject).Any());

            var isAfterRuleShortDate = new Rule("Is After Short Rule")
            {
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("SignatureStatus.SigningCertificate.NotAfter", OPERATION.IS_AFTER)
                    {
                        Data = new List<string>()
                        {
                            DateTime.Now.AddDays(1).ToShortDateString()
                        }
                    }
                }
            };

            var isAfterShortAnalyzer = GetAnalyzerForRule(isAfterRuleShortDate);

            Assert.IsTrue(isAfterShortAnalyzer.Analyze(trueIsAfterObject).Any());
            Assert.IsFalse(isAfterShortAnalyzer.Analyze(falseIsAfterObject).Any());
        }

        [TestMethod]
        public void VerifyIsExpiredOperator()
        {
            var trueIsExpiredObject = new CompareResult()
            {
                Base = new FileSystemObject("App.exe")
                {
                    SignatureStatus = new Signature(true)
                    {
                        SigningCertificate = new SerializableCertificate(Thumbprint: string.Empty, Subject: string.Empty, PublicKey: string.Empty, NotAfter: DateTime.MinValue, NotBefore: DateTime.Now, Issuer: string.Empty, SerialNumber: string.Empty, CertHashString: string.Empty, Pkcs7: string.Empty)
                    }
                }
            };

            var falseIsExpiredObject = new CompareResult()
            {
                Base = new FileSystemObject("App.exe")
                {
                    SignatureStatus = new Signature(true)
                    {
                        SigningCertificate = new SerializableCertificate(Thumbprint: string.Empty, Subject: string.Empty, PublicKey: string.Empty, NotAfter: DateTime.MaxValue, NotBefore: DateTime.Now, Issuer: string.Empty, SerialNumber: string.Empty, CertHashString: string.Empty, Pkcs7: string.Empty)
                    }
                }
            };

            var isExpiredRule = new Rule("Is Expired Rule")
            {
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("SignatureStatus.SigningCertificate.NotAfter", OPERATION.IS_EXPIRED)
                }
            };

            var isExpiredAnalyzer = GetAnalyzerForRule(isExpiredRule);

            Assert.IsTrue(isExpiredAnalyzer.Analyze(trueIsExpiredObject).Any());
            Assert.IsFalse(isExpiredAnalyzer.Analyze(falseIsExpiredObject).Any());
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
