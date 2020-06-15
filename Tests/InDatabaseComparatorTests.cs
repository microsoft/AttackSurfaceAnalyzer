// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using AttackSurfaceAnalyzer.Collectors;
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
using System.Threading;

namespace AttackSurfaceAnalyzer.Tests
{
    [TestClass]
    public class InDatabaseComparatorTests
    {
        [ClassInitialize]
        public static void ClassSetup(TestContext _)
        {
            Logger.Setup(false, true);
            Strings.Setup();
            AsaTelemetry.Setup(test: true);
        }

        [TestMethod]
        public void TestAddedInDatabase()
        {
            var elo2 = new EventLogObject("Entry")
            {
                Timestamp = DateTime.Now.AddYears(1)
            };

            DatabaseManager.Write(elo2, "SecondRun");

            // Let Database Finish Writing
            Thread.Sleep(1);

            BaseCompare bc = new BaseCompare();
            bc.Compare("FirstRun", "SecondRun");

            var results = bc.Results;

            Assert.IsTrue(results[(RESULT_TYPE.LOG, CHANGE_TYPE.CREATED)].Any(x => x.Compare is EventLogObject));
        }

        [TestCleanup]
        public void TestCleanup()
        {
            DatabaseManager.Destroy();
        }

        [TestMethod]
        public void TestModifiedInDatabase()
        {
            var elo = new EventLogObject("Entry")
            {
                Timestamp = DateTime.Now
            };
            var elo2 = new EventLogObject("Entry")
            {
                Timestamp = DateTime.Now.AddYears(1)
            };

            DatabaseManager.Write(elo, "FirstRun");
            DatabaseManager.Write(elo2, "SecondRun");

            // Let Database Finish Writing
            Thread.Sleep(1);

            BaseCompare bc = new BaseCompare();
            bc.Compare("FirstRun", "SecondRun");

            var results = bc.Results;

            Assert.IsTrue(results[(RESULT_TYPE.LOG, CHANGE_TYPE.MODIFIED)].Any(x => x.Compare is EventLogObject));
        }

        [TestMethod]
        public void TestRemovedInDatabase()
        {
            var elo = new EventLogObject("Entry")
            {
                Timestamp = DateTime.Now
            };

            DatabaseManager.Write(elo, "FirstRun");

            // Let Database Finish Writing
            Thread.Sleep(1);

            BaseCompare bc = new BaseCompare();
            bc.Compare("FirstRun", "SecondRun");

            var results = bc.Results;

            Assert.IsTrue(results[(RESULT_TYPE.LOG, CHANGE_TYPE.DELETED)].Any(x => x.Base is EventLogObject));
        }

        [TestInitialize]
        public void TestSetup()
        {
            DatabaseManager.Setup("db.name", new DBSettings() { ShardingFactor = 1 });
        }
    }
}