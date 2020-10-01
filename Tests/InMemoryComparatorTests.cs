// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Collectors;
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Tests
{
    [TestClass]
    public class InMemoryComparatorTests
    {
        [ClassInitialize]
        public static void ClassSetup(TestContext _)
        {
            Logger.Setup(false, true);
            Strings.Setup();
        }

        [TestMethod]
        public void TestAddedInMemory()
        {
            var elo2 = new EventLogObject("Entry")
            {
                Timestamp = DateTime.Now.AddYears(1)
            };

            BaseCompare bc = new BaseCompare();
            bc.Compare(new List<CollectObject>() { }, new List<CollectObject>() { elo2 }, "FirstRun", "SecondRun");

            var results = bc.Results;

            Assert.IsTrue(results[(RESULT_TYPE.LOG, CHANGE_TYPE.CREATED)].Any(x => x.Compare is EventLogObject));
        }

        [TestMethod]
        public void TestModifiedInMemory()
        {
            var elo = new EventLogObject("Entry")
            {
                Timestamp = DateTime.Now
            };
            var elo2 = new EventLogObject("Entry")
            {
                Timestamp = DateTime.Now.AddYears(1)
            };

            BaseCompare bc = new BaseCompare();
            bc.Compare(new List<CollectObject>() { elo }, new List<CollectObject>() { elo2 }, "FirstRun", "SecondRun");

            var results = bc.Results;

            Assert.IsTrue(results[(RESULT_TYPE.LOG, CHANGE_TYPE.MODIFIED)].Any(x => x.Compare is EventLogObject));
        }

        [TestMethod]
        public void TestRemovedInMemory()
        {
            var elo = new EventLogObject("Entry")
            {
                Timestamp = DateTime.Now
            };

            BaseCompare bc = new BaseCompare();
            bc.Compare(new List<CollectObject>() { elo }, new List<CollectObject>() { }, "FirstRun", "SecondRun");

            var results = bc.Results;

            Assert.IsTrue(results[(RESULT_TYPE.LOG, CHANGE_TYPE.DELETED)].Any(x => x.Base is EventLogObject));
        }
    }
}