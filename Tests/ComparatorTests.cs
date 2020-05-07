// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Collectors;
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.Win32;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace AttackSurfaceAnalyzer.Tests
{
    [TestClass]
    public class ComparatorTests
    {
        [TestInitialize]
        public void Setup()
        {
            Logger.Setup(false, true);
            Strings.Setup();
            AsaTelemetry.Setup(test: true);
            DatabaseManager.Setup(Path.GetTempFileName());
        }

        [TestCleanup]
        public void TearDown()
        {
            DatabaseManager.Destroy();
        }

        [TestMethod]
        public void TestListOfStringsCompare()
        {
            var FirstRunId = "TestFileCollector-1";
            var SecondRunId = "TestFileCollector-2";

            var NewItems = new List<CollectObject>(){
                new RegistryObject("UnchangedEntry", RegistryView.Default)
                {
                    Subkeys = new List<string>()
                    {
                        "UnchangedKey"
                    }
                },
                new RegistryObject("ChangingEntry", RegistryView.Default)
                {
                    Subkeys = new List<string>()
                    {
                        "KeyTwo"
                    }
                }
            };
            var OldItems = new List<CollectObject>(){
                new RegistryObject("UnchangedEntry", RegistryView.Default)
                {
                    Subkeys = new List<string>()
                    {
                        "UnchangedKey"
                    }
                },
                new RegistryObject("ChangingEntry", RegistryView.Default)
                {
                    Subkeys = new List<string>()
                    {
                        "KeyOne"
                    }
                }
            };

            BaseCompare bc = new BaseCompare();
            bc.Compare(OldItems, NewItems, FirstRunId, SecondRunId);
            var results = bc.Results;

            Assert.IsTrue(results[(RESULT_TYPE.REGISTRY, CHANGE_TYPE.MODIFIED)].Any(x => x.Identity.Contains("ChangingEntry") && x.Base is RegistryObject FSO && x.Compare is RegistryObject FSO2 && FSO.Subkeys.Contains("KeyOne") && FSO2.Subkeys.Contains("KeyTwo")));
            Assert.IsTrue(results[(RESULT_TYPE.REGISTRY, CHANGE_TYPE.MODIFIED)].Any(x => x.Diffs.Any(y => y.Field == "Subkeys") && x.Identity.Contains("ChangingEntry")));
            Assert.IsFalse(results[(RESULT_TYPE.REGISTRY, CHANGE_TYPE.MODIFIED)].Any(x => x.Identity.Contains("UnchangedEntry")));
        }

        [TestMethod]
        public void TestDictionaryOfStringsCompare()
        {
            var FirstRunId = "TestFileCollector-1";
            var SecondRunId = "TestFileCollector-2";

            var NewItems = new List<CollectObject>(){
                new FileSystemObject("UnchangedEntry")
                {
                    Permissions = new Dictionary<string, string>()
                    {
                        { "User","Read" }
                    }
                },
                new FileSystemObject("ChangingEntry")
                {
                    Permissions = new Dictionary<string, string>()
                    {
                        { "User","ReadWrite" }
                    }
                }
            };
            var OldItems = new List<CollectObject>(){
                new FileSystemObject("UnchangedEntry")
                {
                    Permissions = new Dictionary<string, string>()
                    {
                        { "User","Read" }
                    }
                },
                new FileSystemObject("ChangingEntry")
                {
                    Permissions = new Dictionary<string, string>()
                    {
                        { "User","Read" }
                    }
                }
            };

            BaseCompare bc = new BaseCompare();
            bc.Compare(OldItems, NewItems, FirstRunId, SecondRunId);
            var results = bc.Results;

            Assert.IsTrue(results[(RESULT_TYPE.FILE, CHANGE_TYPE.MODIFIED)].Any(x => x.Identity.Equals("ChangingEntry") && x.Base is FileSystemObject FSO && x.Compare is FileSystemObject FSO2 && FSO.Permissions.ContainsValue("Read") && FSO2.Permissions.ContainsValue("ReadWrite")));
            Assert.IsTrue(results[(RESULT_TYPE.FILE, CHANGE_TYPE.MODIFIED)].Any(x => x.Diffs.Any(y => y.Field == "Permissions") && x.Identity.Equals("ChangingEntry")));
            Assert.IsFalse(results[(RESULT_TYPE.FILE, CHANGE_TYPE.MODIFIED)].Any(x => x.Identity.Equals("UnchangedEntry")));
        }

        [TestMethod]
        public void TestStringCompare()
        {
            var FirstRunId = "TestFileCollector-1";
            var SecondRunId = "TestFileCollector-2";

            var NewItems = new List<CollectObject>(){
                new FileSystemObject("ChangingEntry")
                {
                    PermissionsString = "Unchanged"
                },
                new FileSystemObject("UnchangedEntry")
                {
                    PermissionsString = "After"
                }
            };
            var OldItems = new List<CollectObject>(){
                new FileSystemObject("ChangingEntry")
                {
                    PermissionsString = "Unchanged"
                },
                new FileSystemObject("UnchangedEntry")
                {
                    PermissionsString = "Before"
                }
            };

            BaseCompare bc = new BaseCompare();
            bc.Compare(OldItems, NewItems, FirstRunId, SecondRunId);
            var results = bc.Results;

            Assert.IsTrue(results[(RESULT_TYPE.FILE, CHANGE_TYPE.MODIFIED)].Any(x => x.Identity.Contains("UnchangedEntry") && x.Base is FileSystemObject FSO && x.Compare is FileSystemObject FSO2 && FSO.PermissionsString == "Before" && FSO2.PermissionsString == "After"));
            Assert.IsTrue(results[(RESULT_TYPE.FILE, CHANGE_TYPE.MODIFIED)].Any(x => x.Diffs.Any(y => y.Field == "PermissionsString") && x.Identity.Contains("UnchangedEntry")));
            Assert.IsFalse(results[(RESULT_TYPE.FILE, CHANGE_TYPE.MODIFIED)].Any(x => x.Identity.Contains("ChangingEntry")));
        }

        [TestMethod]
        public void TestBoolCompare()
        {
            var FirstRunId = "TestFileCollector-1";
            var SecondRunId = "TestFileCollector-2";

            var NewItems = new List<CollectObject>(){
                new FileSystemObject("ChangingEntry")
                {
                    IsExecutable = true,
                },
                new FileSystemObject("UnchangedEntry")
                {
                    IsExecutable = false,
                }
            };
            var OldItems = new List<CollectObject>(){
                new FileSystemObject("ChangingEntry")
                {
                    IsExecutable = true,
                },
                new FileSystemObject("UnchangedEntry")
                {
                    IsExecutable = true,
                }
            };

            BaseCompare bc = new BaseCompare();
            bc.Compare(OldItems, NewItems, FirstRunId, SecondRunId);
            var results = bc.Results;

            Assert.IsTrue(results[(RESULT_TYPE.FILE, CHANGE_TYPE.MODIFIED)].Any(x => x.Identity.Contains("UnchangedEntry") && x.Base is FileSystemObject FSO && x.Compare is FileSystemObject FSO2 && FSO.IsExecutable == true && FSO2.IsExecutable == false));
            Assert.IsTrue(results[(RESULT_TYPE.FILE, CHANGE_TYPE.MODIFIED)].Any(x => x.Diffs.Any(y => y.Field == "IsExecutable") && x.Identity.Contains("UnchangedEntry")));
            Assert.IsFalse(results[(RESULT_TYPE.FILE, CHANGE_TYPE.MODIFIED)].Any(x => x.Identity.Contains("ChangingEntry")));
        }

        [TestMethod]
        public void TestAddedDeleted()
        {
            var FirstRunId = "TestFileCollector-1";
            var SecondRunId = "TestFileCollector-2";

            var NewItems = new List<CollectObject>(){
                new FileSystemObject("SecondEntry")
                {
                    IsExecutable = true,
                }
            };
            var OldItems = new List<CollectObject>(){
                new FileSystemObject("FirstEntry")
                {
                    IsExecutable = true,
                }
            };

            BaseCompare bc = new BaseCompare();
            bc.Compare(OldItems, NewItems, FirstRunId, SecondRunId);
            var results = bc.Results;

            Assert.IsTrue(results[(RESULT_TYPE.FILE, CHANGE_TYPE.CREATED)].Any(x => x.Compare is FileSystemObject FSO && FSO.Identity.Contains("SecondEntry") && FSO.IsExecutable == true));
            Assert.IsTrue(results[(RESULT_TYPE.FILE, CHANGE_TYPE.DELETED)].Any(x => x.Base is FileSystemObject FSO && FSO.Identity.Contains("FirstEntry") && FSO.IsExecutable == true));
        }


        [TestMethod]
        public void TestIntCompare()
        {
            var FirstRunId = "TestFileCollector-1";
            var SecondRunId = "TestFileCollector-2";

            var NewItems = new List<CollectObject>(){
                new FileSystemObject("UnchangedEntry"),
                new FileSystemObject("ChangingEntry")
                {
                    Size = 701
                }
            };
            var OldItems = new List<CollectObject>(){
                new FileSystemObject("UnchangedEntry"),
                new FileSystemObject("ChangingEntry")
                {
                    Size = 501
                }
            };

            BaseCompare bc = new BaseCompare();
            bc.Compare(OldItems, NewItems, FirstRunId, SecondRunId);
            var results = bc.Results;

            Assert.IsTrue(results[(RESULT_TYPE.FILE, CHANGE_TYPE.MODIFIED)].Any(x => x.Identity.Contains("ChangingEntry") && x.Base is FileSystemObject FSO && x.Compare is FileSystemObject FSO2 && FSO.Size == 501 && FSO2.Size == 701));
            Assert.IsTrue(results[(RESULT_TYPE.FILE, CHANGE_TYPE.MODIFIED)].Any(x => x.Diffs.Any(y => y.Field == "Size") && x.Identity.Contains("ChangingEntry")));
            Assert.IsFalse(results[(RESULT_TYPE.FILE, CHANGE_TYPE.MODIFIED)].Any(x => x.Identity.Contains("UnchangedEntry")));
        }
    }
}
