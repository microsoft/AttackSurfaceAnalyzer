// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.CST.LogicalAnalyzer;
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
            AsaTelemetry.SetEnabled(enabled: false);
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

            var stringContains = new AsaRule("String Contains Any Rule")
            {
                Target = "FileSystemObject",
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

            var stringAnalyzer = new AsaAnalyzer();
            var ruleList = new List<Rule>() { stringContains }; ;

            Assert.IsTrue(stringAnalyzer.Analyze(ruleList, trueStringObject).Any());
            Assert.IsTrue(stringAnalyzer.Analyze(ruleList, alsoTrueStringObject).Any());
            Assert.IsFalse(stringAnalyzer.Analyze(ruleList, falseStringObject).Any());

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

            var listContains = new AsaRule("List Contains Any Rule")
            {
                Target = "RegistryObject",
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

            var listAnalyzer = new AsaAnalyzer();
            ruleList = new List<Rule>() { listContains }; ;

            Assert.IsTrue(listAnalyzer.Analyze(ruleList, trueListObject).Any());
            Assert.IsTrue(listAnalyzer.Analyze(ruleList, alsoTrueListObject).Any());
            Assert.IsFalse(listAnalyzer.Analyze(ruleList, falseListObject).Any());

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

            var stringDictContains = new AsaRule("String Dict Contains Any Rule")
            {
                Target = "RegistryObject",
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

            var stringDictAnalyzer = new AsaAnalyzer();
            ruleList = new List<Rule>() { stringDictContains }; ;

            Assert.IsTrue(stringDictAnalyzer.Analyze(ruleList, trueStringDictObject).Any());
            Assert.IsTrue(stringDictAnalyzer.Analyze(ruleList, alsoTrueStringDict).Any());
            Assert.IsFalse(stringDictAnalyzer.Analyze(ruleList, superFalseStringDictObject).Any());

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

            var listDictContains = new AsaRule("List Dict Contains Any Rule")
            {
                Target = "RegistryObject",
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

            var listDictAnalyzer = new AsaAnalyzer();
            ruleList = new List<Rule>() { listDictContains }; ;

            Assert.IsTrue(listDictAnalyzer.Analyze(ruleList, trueListDictObject).Any());
            Assert.IsTrue(listDictAnalyzer.Analyze(ruleList, alsoTrueListDictObject).Any());
            Assert.IsFalse(listDictAnalyzer.Analyze(ruleList, falseListDictObject).Any());
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

            var algDictContains = new AsaRule("Alg Dict Changed PCR 1")
            {
                Target = "TpmObject",
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

            var algDictAnalyzer = new AsaAnalyzer();
            var ruleList = new List<Rule>() { algDictContains }; ;

            Assert.IsTrue(algDictAnalyzer.Analyze(ruleList, trueAlgDict).Any());
            Assert.IsFalse(algDictAnalyzer.Analyze(ruleList, falseAlgDict).Any());
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

            var stringContains = new AsaRule("String Contains Rule")
            {
                Target = "FileSystemObject",
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

            var stringAnalyzer = new AsaAnalyzer();
            var ruleList = new List<Rule>() { stringContains }; ;

            Assert.IsTrue(stringAnalyzer.Analyze(ruleList, trueStringObject).Any());
            Assert.IsFalse(stringAnalyzer.Analyze(ruleList, falseStringObject).Any());
            Assert.IsFalse(stringAnalyzer.Analyze(ruleList, superFalseStringObject).Any());

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

            var listContains = new AsaRule("List Contains Rule")
            {
                Target = "RegistryObject",
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

            var listAnalyzer = new AsaAnalyzer();
            ruleList = new List<Rule>() { listContains }; ;

            Assert.IsTrue(listAnalyzer.Analyze(ruleList, trueListObject).Any());
            Assert.IsFalse(listAnalyzer.Analyze(ruleList, falseListObject).Any());
            Assert.IsFalse(listAnalyzer.Analyze(ruleList, superFalseListObject).Any());

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

            var stringDictContains = new AsaRule("String Dict Contains Rule")
            {
                Target = "RegistryObject",
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

            var stringDictAnalyzer = new AsaAnalyzer();
            ruleList = new List<Rule>() { stringDictContains }; ;

            Assert.IsTrue(stringDictAnalyzer.Analyze(ruleList, trueStringDictObject).Any());
            Assert.IsFalse(stringDictAnalyzer.Analyze(ruleList, falseStringDictObject).Any());
            Assert.IsFalse(stringDictAnalyzer.Analyze(ruleList, superFalseStringDictObject).Any());

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

            var listDictContains = new AsaRule("List Dict Contains Rule")
            {
                Target = "RegistryObject",
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

            var listDictAnalyzer = new AsaAnalyzer();
            ruleList = new List<Rule>() { listDictContains }; ;

            Assert.IsTrue(listDictAnalyzer.Analyze(ruleList, trueListDictObject).Any());
            Assert.IsFalse(listDictAnalyzer.Analyze(ruleList, falseListDictObject).Any());
            Assert.IsFalse(listDictAnalyzer.Analyze(ruleList, alsoFalseListDictObject).Any());
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

            var endsWithRule = new AsaRule("Ends With Rule")
            {
                Target = "FileSystemObject",
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

            var endsWithAnalyzer = new AsaAnalyzer();
            var ruleList = new List<Rule>() { endsWithRule }; ;

            Assert.IsTrue(endsWithAnalyzer.Analyze(ruleList, trueEndsWithObject).Any());
            Assert.IsFalse(endsWithAnalyzer.Analyze(ruleList, falseEndsWithObject).Any());
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

            var stringEquals = new AsaRule("String Equals Rule")
            {
                Target = "FileSystemObject",
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

            var boolEquals = new AsaRule("Bool Equals Rule")
            {
                Target = "FileSystemObject",
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

            var intEquals = new AsaRule("Int Equals Rule")
            {
                Target = "FileSystemObject",
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

            var analyzer = new AsaAnalyzer();
            var ruleList = new List<Rule>() { boolEquals , intEquals, stringEquals };

            var trueObjectResults = analyzer.Analyze(ruleList, assertTrueObject);
            var falseObjectResults = analyzer.Analyze(ruleList, assertFalseObject);

            Assert.IsTrue(trueObjectResults.Any(x => x.Name == "Bool Equals Rule"));
            Assert.IsTrue(trueObjectResults.Any(x => x.Name == "Int Equals Rule"));
            Assert.IsTrue(trueObjectResults.Any(x => x.Name == "String Equals Rule"));

            Assert.IsFalse(falseObjectResults.Any(x => x.Name == "Bool Equals Rule"));
            Assert.IsFalse(falseObjectResults.Any(x => x.Name == "Int Equals Rule"));
            Assert.IsFalse(falseObjectResults.Any(x => x.Name == "String Equals Rule"));
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

            var gtRule = new AsaRule("Gt Rule")
            {
                Target = "OpenPortObject",
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

            var badGtRule = new AsaRule("Bad Gt Rule")
            {
                Target = "OpenPortObject",
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

            var gtAnalyzer = new AsaAnalyzer();
            var ruleList = new List<Rule>() { gtRule }; ;

            Assert.IsTrue(gtAnalyzer.Analyze(ruleList, trueGtObject).Any());
            Assert.IsFalse(gtAnalyzer.Analyze(ruleList, falseGtObject).Any());

            var badGtAnalyzer = new AsaAnalyzer();
            ruleList = new List<Rule>() { badGtRule }; ;

            Assert.IsFalse(badGtAnalyzer.Analyze(ruleList, trueGtObject).Any());
            Assert.IsFalse(badGtAnalyzer.Analyze(ruleList, falseGtObject).Any());
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

            var isAfterRule = new AsaRule("Is After Rule")
            {
                Target = "FileSystemObject",
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

            var isAfterAnalyzer = new AsaAnalyzer();
            var ruleList = new List<Rule>() { isAfterRule }; ;

            Assert.IsTrue(isAfterAnalyzer.Analyze(ruleList, trueIsAfterObject).Any());
            Assert.IsFalse(isAfterAnalyzer.Analyze(ruleList, falseIsAfterObject).Any());

            var isAfterRuleShortDate = new AsaRule("Is After Short Rule")
            {
                Target = "FileSystemObject",
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

            var isAfterShortAnalyzer = new AsaAnalyzer();
            ruleList = new List<Rule>() { isAfterRuleShortDate }; ;

            Assert.IsTrue(isAfterShortAnalyzer.Analyze(ruleList, trueIsAfterObject).Any());
            Assert.IsFalse(isAfterShortAnalyzer.Analyze(ruleList, falseIsAfterObject).Any());
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

            var isBeforeRule = new AsaRule("Is Before Rule")
            {
                Target = "FileSystemObject",
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

            var isBeforeAnalyzer = new AsaAnalyzer();
            var ruleList = new List<Rule>() { isBeforeRule }; ;

            Assert.IsTrue(isBeforeAnalyzer.Analyze(ruleList, trueIsBeforeObject).Any());
            Assert.IsFalse(isBeforeAnalyzer.Analyze(ruleList, falseIsBeforeObject).Any());

            var isBeforeShortRule = new AsaRule("Is Before Short Rule")
            {
                Target = "FileSystemObject",
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

            var isBeforeShortAnalyzer = new AsaAnalyzer();
            ruleList = new List<Rule>() { isBeforeShortRule }; ;

            Assert.IsTrue(isBeforeShortAnalyzer.Analyze(ruleList, trueIsBeforeObject).Any());
            Assert.IsFalse(isBeforeShortAnalyzer.Analyze(ruleList, falseIsBeforeObject).Any());
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

            var isExpiredRule = new AsaRule("Is Expired Rule")
            {
                Target = "FileSystemObject",
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("SignatureStatus.SigningCertificate.NotAfter", OPERATION.IS_EXPIRED)
                }
            };

            var isExpiredAnalyzer = new AsaAnalyzer();
            var ruleList = new List<Rule>() { isExpiredRule }; ;

            Assert.IsTrue(isExpiredAnalyzer.Analyze(ruleList, trueIsExpiredObject).Any());
            Assert.IsFalse(isExpiredAnalyzer.Analyze(ruleList, falseIsExpiredObject).Any());
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

            var isNullRule = new AsaRule("Is Null Rule")
            {
                Target = "FileSystemObject",
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("ContentHash", OPERATION.IS_NULL)
                }
            };

            var isNullAnalyzer = new AsaAnalyzer();
            var ruleList = new List<Rule>() { isNullRule }; ;

            Assert.IsTrue(isNullAnalyzer.Analyze(ruleList, trueIsNullObject).Any());
            Assert.IsFalse(isNullAnalyzer.Analyze(ruleList, falseIsNullObject).Any());
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

            var isTrueRule = new AsaRule("Is True Rule")
            {
                Target = "FileSystemObject",
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("IsExecutable", OPERATION.IS_TRUE)
                }
            };

            var isTrueAnalyzer = new AsaAnalyzer();
            var ruleList = new List<Rule>() { isTrueRule }; ;

            Assert.IsTrue(isTrueAnalyzer.Analyze(ruleList, trueIsTrueObject).Any());
            Assert.IsFalse(isTrueAnalyzer.Analyze(ruleList, falseIsTrueObject).Any());
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

            var ltRule = new AsaRule("Lt Rule")
            {
                Target = "OpenPortObject",
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

            var ltAnalyzer = new AsaAnalyzer();
            var ruleList = new List<Rule>() { ltRule }; ;

            Assert.IsTrue(ltAnalyzer.Analyze(ruleList, trueLtObject).Any());
            Assert.IsFalse(ltAnalyzer.Analyze(ruleList, falseLtObject).Any());

            var badLtRule = new AsaRule("Bad Lt Rule")
            {
                Target = "OpenPortObject",
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

            var badLtAnalyzer = new AsaAnalyzer();
            ruleList = new List<Rule>() { badLtRule }; ;

            Assert.IsFalse(badLtAnalyzer.Analyze(ruleList, trueLtObject).Any());
            Assert.IsFalse(badLtAnalyzer.Analyze(ruleList, falseLtObject).Any());
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

            var stringEquals = new AsaRule("String Equals Rule")
            {
                Target = "FileSystemObject",
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

            var boolEquals = new AsaRule("Bool Equals Rule")
            {
                Target = "FileSystemObject",
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

            var intEquals = new AsaRule("Int Equals Rule")
            {
                Target = "FileSystemObject",
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

            var analyzer = new AsaAnalyzer();
            var ruleList = new List<Rule>() { boolEquals, intEquals, stringEquals }; ;

            Assert.IsFalse(analyzer.Analyze(ruleList, assertTrueObject).Any(x => x.Name == "Bool Equals Rule"));
            Assert.IsFalse(analyzer.Analyze(ruleList, assertTrueObject).Any(x => x.Name == "Int Equals Rule"));
            Assert.IsFalse(analyzer.Analyze(ruleList, assertTrueObject).Any(x => x.Name == "String Equals Rule"));

            Assert.IsTrue(analyzer.Analyze(ruleList, assertFalseObject).Any(x => x.Name == "Bool Equals Rule"));
            Assert.IsTrue(analyzer.Analyze(ruleList, assertFalseObject).Any(x => x.Name == "Int Equals Rule"));
            Assert.IsTrue(analyzer.Analyze(ruleList, assertFalseObject).Any(x => x.Name == "String Equals Rule"));
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

            var regexRule = new AsaRule("Regex Rule")
            {
                Target = "FileSystemObject",
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

            var regexAnalyzer = new AsaAnalyzer();
            var ruleList = new List<Rule>() { regexRule }; ;

            Assert.IsTrue(regexAnalyzer.Analyze(ruleList, trueRegexObject).Any());
            Assert.IsFalse(regexAnalyzer.Analyze(ruleList, falseRegexObject).Any());
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

            var endsWithRule = new AsaRule("Ends With Rule")
            {
                Target = "FileSystemObject",
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

            var endsWithAnalyzer = new AsaAnalyzer();
            var ruleList = new List<Rule>() { endsWithRule }; ;

            Assert.IsTrue(endsWithAnalyzer.Analyze(ruleList, trueEndsWithObject).Any());
            Assert.IsFalse(endsWithAnalyzer.Analyze(ruleList, falseEndsWithObject).Any());
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

            var wasModifiedRule = new AsaRule("Was Modified Rule")
            {
                Target = "FileSystemObject",
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("IsExecutable", OPERATION.WAS_MODIFIED)
                }
            };

            var regexAnalyzer = new AsaAnalyzer();
            var ruleList = new List<Rule>() { wasModifiedRule }; ;

            Assert.IsTrue(regexAnalyzer.Analyze(ruleList, trueModifiedObject).Any());
            Assert.IsFalse(regexAnalyzer.Analyze(ruleList, falseModifiedObject).Any());
            Assert.IsFalse(regexAnalyzer.Analyze(ruleList, alsoFalseModifiedObject).Any());

            var trueAlgDict = new CompareResult()
            {
                Base = new TpmObject("TestLocal")
                {
                    PCRs = new Dictionary<(Tpm2Lib.TpmAlgId, uint), byte[]>()
                    {
                        { (TpmAlgId.Sha,1), new byte[5] { 1,2,3,4,5 } }
                    }
                },
                Compare = new TpmObject("TestLocal")
                {
                    PCRs = new Dictionary<(Tpm2Lib.TpmAlgId, uint), byte[]>()
                    {
                        { (TpmAlgId.Sha,1), new byte[5] { 0,0,0,0,0 } }
                    }
                }
            };

            var falseAlgDict = new CompareResult()
            {
                Base = new TpmObject("TestLocal")
                {
                    PCRs = new Dictionary<(Tpm2Lib.TpmAlgId, uint), byte[]>()
                    {
                        { (TpmAlgId.Sha,1), new byte[5] { 1,2,3,4,5 } }
                    }
                },
                Compare = new TpmObject("TestLocal")
                {
                    PCRs = new Dictionary<(Tpm2Lib.TpmAlgId, uint), byte[]>()
                    {
                        { (TpmAlgId.Sha,1), new byte[5] { 1, 2, 3, 4, 5 } }
                    }
                }
            };

            var pcrsModified = new AsaRule("Alg Dict Changed PCR 1")
            {
                Target = "TpmObject",
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause("PCRs.(Sha, 1)", OPERATION.WAS_MODIFIED)
                }
            };

            var pcrAnalyzer = new AsaAnalyzer();
            ruleList = new List<Rule>() { pcrsModified };

            Assert.IsTrue(pcrAnalyzer.Analyze(ruleList, trueAlgDict).Any());
            Assert.IsFalse(pcrAnalyzer.Analyze(ruleList, falseAlgDict).Any());
        }
    }
}