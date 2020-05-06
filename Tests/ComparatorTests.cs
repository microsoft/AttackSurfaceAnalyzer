// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Collectors;
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.Win32;
using Newtonsoft.Json;
using Serilog;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using WindowsFirewallHelper;

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

        // TODO: Write more tests for better coverage

        [TestMethod]
        public void TestFileCompare()
        {
            var FirstRunId = "TestFileCollector-1";
            var SecondRunId = "TestFileCollector-2";

            var testFolder = AsaHelpers.GetTempFolder();
            Directory.CreateDirectory(testFolder);

            var opts = new CollectCommandOptions()
            {
                RunId = FirstRunId,
                EnableFileSystemCollector = true,
                GatherHashes = true,
                SelectedDirectories = testFolder,
                DownloadCloud = false,
            };

            var NewItems = new List<CollectObject>(){
                new FileSystemObject("TestPath2")
                {
                    IsExecutable = true,
                    Size = 701
                },
                new FileSystemObject("TestPath3")
                {
                    IsExecutable = false,
                    Size = 701
                },
                new FileSystemObject("TestPath4")
                {
                    IsExecutable = false,
                    Size = 701
                }
            };
            var OldItems = new List<CollectObject>(){
                new FileSystemObject("TestPath2")
                {
                    IsExecutable = true,
                    Size = 701
                },
                new FileSystemObject("TestPath")
                {
                    IsExecutable = false,
                    Size = 701
                },
                new FileSystemObject("TestPath4")
                {
                    IsExecutable = true,
                    Size = 701
                }
            };

            BaseCompare bc = new BaseCompare();
            bc.Compare(OldItems, NewItems, FirstRunId, SecondRunId);
            var results = bc.Results;

            Assert.IsTrue(results[(RESULT_TYPE.FILE, CHANGE_TYPE.CREATED)].Any(x => x.Compare is FileSystemObject FSO && FSO.Identity.Contains("TestPath3") && FSO.Size == 701));
            Assert.IsTrue(results[(RESULT_TYPE.FILE, CHANGE_TYPE.DELETED)].Any(x => x.Base is FileSystemObject FSO && FSO.Identity.Contains("TestPath") && FSO.Size == 701));
            Assert.IsTrue(results[(RESULT_TYPE.FILE, CHANGE_TYPE.MODIFIED)].Any(x => x.Identity.Contains("TestPath4") && x.Compare is FileSystemObject FSO && x.Base is FileSystemObject FSO2 && FSO.IsExecutable == false && FSO2.IsExecutable == true));
            Assert.IsTrue(results[(RESULT_TYPE.FILE, CHANGE_TYPE.MODIFIED)].Any(x => x.Diffs.Any(y => y.Field == "IsExecutable") && x.Identity.Contains("TestPath4")));
            Assert.IsFalse(results[(RESULT_TYPE.FILE, CHANGE_TYPE.MODIFIED)].Any(x => x.Identity.Contains("TestPath2")));
        }
    }
}
