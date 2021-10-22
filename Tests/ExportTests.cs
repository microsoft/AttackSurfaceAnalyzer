// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Cli;
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Tests
{
    [TestClass]
    public class ExportTests
    {
        [ClassInitialize]
        public static void ClassSetup(TestContext _)
        {
            Logger.Setup(false, true);
            Strings.Setup();
        }

        /// <summary>
        ///     Does not require admin.
        /// </summary>
        [TestMethod]
        public void TestGenerateSarifLog()
        {
            JsonSerializerSettings jsonSettings = new JsonSerializerSettings()
            {
                Formatting = Formatting.Indented,
                TypeNameHandling = TypeNameHandling.Auto,
                NullValueHandling = NullValueHandling.Ignore,
                DefaultValueHandling = DefaultValueHandling.Ignore,
                DateFormatHandling = DateFormatHandling.IsoDateFormat
            };

            var outputJson = File.ReadAllText(@"TestData\ExportTests\TestGenerateSarifLog\output.json");
            var rulesJson = File.ReadAllText(@"TestData\ExportTests\TestGenerateSarifLog\rules.json");
            var outputDictionary = JsonConvert.DeserializeObject<Dictionary<string, object>>(outputJson, jsonSettings);
            var rulesList = JsonConvert.DeserializeObject<IEnumerable<AsaRule>>(rulesJson, jsonSettings);

            var sarif = AttackSurfaceAnalyzerClient.GenerateSarifLog(outputDictionary, rulesList);

            Assert.AreEqual(sarif.Runs[0].Artifacts.Count, 3);
            Assert.IsTrue(sarif.Runs[0].Artifacts.Any(a => a.Location.Description.Text == "C:\\Test\\Scan2\\TestAddText.txt"));
            Assert.IsTrue(sarif.Runs[0].Artifacts.Any(a => a.Location.Description.Text == "C:\\Test\\Scan2\\TestAddExe.exe"));
            Assert.IsTrue(sarif.Runs[0].Artifacts.Any(a => a.Location.Description.Text == "C:\\Test\\Scan2\\TestModifyExe.exe"));
            Assert.AreEqual(sarif.Runs[0].Results.Count, 6);
            Assert.IsTrue(sarif.Runs[0].Results.Any(r => r.Message.Text == "Missing DEP: C:\\Test\\Scan2\\TestAddExe.exe (CREATED)"));
            Assert.IsTrue(sarif.Runs[0].Results.Any(r => r.Message.Text == "Missing ASLR: C:\\Test\\Scan2\\TestAddExe.exe (CREATED)"));
            Assert.IsTrue(sarif.Runs[0].Results.Any(r => r.Message.Text == "Unsigned binaries: C:\\Test\\Scan2\\TestAddExe.exe (CREATED)"));
            Assert.IsFalse(sarif.Runs[0].Results.Any(r => r.Message.Text.Contains("TestAddText.txt")));
            Assert.AreEqual(sarif.Runs[0].Tool.Driver.Rules.Count, 41);
            Assert.IsTrue(sarif.Runs[0].Tool.Driver.Rules.Any(r => r.FullDescription.Text == "Flag when privileged ports are opened."));
        }
    }
}