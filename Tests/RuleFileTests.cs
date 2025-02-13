// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Collectors;
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.Win32;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using Tpm2Lib;
using WindowsFirewallHelper;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Tests
{
    [TestClass, TestCategory("PipelineSafeTests")]
    public class RuleFileTests
    {
        [ClassInitialize]
        public static void ClassSetup(TestContext _)
        {
            Logger.Setup(false, true);
            Strings.Setup();
        }

        /// <summary>
        ///     Verify that embedded rules have no issues
        /// </summary>
        [TestMethod]
        public void TestEmbeddedRules()
        {
            var rules = RuleFile.LoadEmbeddedFilters();
            var analyzer = new AsaAnalyzer();
            var issues = analyzer.EnumerateRuleIssues(rules.Rules);
            foreach (var issue in issues)
            {
                Console.WriteLine(issue.Description);
            }
            //Verify there are no issues
            Assert.AreEqual(0, issues.Count());
            //Verify that every result type is accounted for in the default levels
            Assert.IsTrue(Enum.GetNames(typeof(RESULT_TYPE)).All(y => rules.GetDefaultLevels().Any(x => x.Key.ToString() == y)));
        }

        [TestMethod]
        public void TestGetDefaultLevels()
        {
            var rules = new RuleFile();
            foreach (RESULT_TYPE enu in Enum.GetValues(typeof(RESULT_TYPE))) 
            {
                Assert.IsTrue(rules.GetDefaultLevel(enu).Equals(rules.DefaultLevel));
            }
        }
    }
}