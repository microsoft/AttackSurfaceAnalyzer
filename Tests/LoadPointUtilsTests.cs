// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Tests
{
    /// <summary>
    ///     Coverage for the pieces of the load point analysis that are platform independent: cracking
    ///     references out of registry values, and deciding whether a principal can write something.
    /// </summary>
    [TestClass, TestCategory("PipelineSafeTests")]
    public class LoadPointUtilsTests
    {
        [ClassInitialize]
        public static void ClassSetup(TestContext _)
        {
            Logger.Setup(false, true);
            Strings.Setup();
        }

        [TestMethod]
        public void ExtractPathsFindsDriveQualifiedPaths()
        {
            var paths = RegistryReferenceParser.ExtractPaths(@"C:\Windows\System32\shell32.dll").ToList();

            Assert.AreEqual(1, paths.Count);
            Assert.AreEqual(@"C:\Windows\System32\shell32.dll", paths[0]);
        }

        [TestMethod]
        public void ExtractPathsExpandsEnvironmentVariables()
        {
            Environment.SetEnvironmentVariable(TestVariable, @"C:\ProgramData");

            try
            {
                var paths = RegistryReferenceParser
                    .ExtractPaths($@"%{TestVariable}%\CrossDevice\CrossDevice.Streaming.Source.dll")
                    .ToList();

                Assert.AreEqual(1, paths.Count);
                Assert.AreEqual(@"C:\ProgramData\CrossDevice\CrossDevice.Streaming.Source.dll", paths[0]);
            }
            finally
            {
                Environment.SetEnvironmentVariable(TestVariable, null);
            }
        }

        [TestMethod]
        public void ExtractPathsKeepsSpacesAndTrimsTrailingArguments()
        {
            var paths = RegistryReferenceParser.ExtractPaths(@"C:\Program Files\Contoso\app.dll,-100").ToList();

            Assert.AreEqual(1, paths.Count);
            Assert.AreEqual(@"C:\Program Files\Contoso\app.dll", paths[0]);
        }

        [TestMethod]
        public void ExtractPathsDoesNotTruncateLongExtensions()
        {
            var paths = RegistryReferenceParser.ExtractPaths(@"C:\a.b\c.config").ToList();

            Assert.AreEqual(1, paths.Count);
            Assert.AreEqual(@"C:\a.b\c.config", paths[0]);
        }

        [TestMethod]
        public void ExtractPathsIgnoresValuesWithoutReferences()
        {
            Assert.AreEqual(0, RegistryReferenceParser.ExtractPaths("1").Count());
            Assert.AreEqual(0, RegistryReferenceParser.ExtractPaths("SomeDisplayName").Count());
            Assert.AreEqual(0, RegistryReferenceParser.ExtractPaths(null).Count());
        }

        [TestMethod]
        public void ExtractPathsSkipsPathologicallyLongValues()
        {
            var value = new string('A', RegistryReferenceParser.MaxScannedValueLength + 1);

            Assert.AreEqual(0, RegistryReferenceParser.ExtractPaths(value).Count());
            Assert.AreEqual(0, RegistryReferenceParser.ExtractClsids(value).Count());
        }

        [TestMethod]
        public void ExtractClsidsNormalizesToBracedUppercase()
        {
            var clsids = RegistryReferenceParser
                .ExtractClsids("PluginId=1;Clsid=e9f83cf2-e0c0-4ca7-af01-e90c70bef496")
                .ToList();

            Assert.AreEqual(1, clsids.Count);
            Assert.AreEqual("{E9F83CF2-E0C0-4CA7-AF01-E90C70BEF496}", clsids[0]);
        }

        [TestMethod]
        public void ExtractClsidsDeduplicates()
        {
            var clsids = RegistryReferenceParser
                .ExtractClsids("{E9F83CF2-E0C0-4CA7-AF01-E90C70BEF496} {e9f83cf2-e0c0-4ca7-af01-e90c70bef496}")
                .ToList();

            Assert.AreEqual(1, clsids.Count);
        }

        [TestMethod]
        public void ExtractExecutablePathHandlesQuotedCommandLines()
        {
            Assert.AreEqual(
                @"C:\Program Files\Contoso\server.exe",
                RegistryReferenceParser.ExtractExecutablePath(@"""C:\Program Files\Contoso\server.exe"" -Embedding"));
        }

        [TestMethod]
        public void ExtractExecutablePathHandlesUnquotedCommandLines()
        {
            Assert.AreEqual(
                @"C:\Windows\System32\svchost.exe",
                RegistryReferenceParser.ExtractExecutablePath(@"C:\Windows\System32\svchost.exe -k netsvcs"));
        }

        [TestMethod]
        public void NormalizePathStripsQuotesAndNativePrefixes()
        {
            Assert.AreEqual(@"C:\Windows\System32\drivers\x.sys", RegistryReferenceParser.NormalizePath(@"\??\C:\Windows\System32\drivers\x.sys"));
            Assert.AreEqual(@"C:\Windows\System32\x.dll", RegistryReferenceParser.NormalizePath(@"  ""C:\Windows\System32\x.dll""  "));
        }

        [TestMethod]
        public void NormalizePathQualifiesBareBinaryNames()
        {
            // Environment.SystemDirectory is empty off Windows, so only the file name is asserted here.
            var normalized = RegistryReferenceParser.NormalizePath("shell32.dll");

            Assert.IsNotNull(normalized);
            Assert.AreEqual("shell32.dll", Path.GetFileName(normalized));

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Assert.IsTrue(normalized!.StartsWith(Environment.SystemDirectory, StringComparison.OrdinalIgnoreCase));
            }
        }

        [TestMethod]
        public void IsNetworkPathDetectsUncPaths()
        {
            Assert.IsTrue(PathUtils.IsNetworkPath(@"\\attacker\share\planted.dll"));
            Assert.IsTrue(PathUtils.IsNetworkPath(@"  \\attacker\share\planted.dll  "));
            Assert.IsTrue(PathUtils.IsNetworkPath(@"\\?\UNC\attacker\share\planted.dll"));
            Assert.IsTrue(PathUtils.IsNetworkPath(@"\\?\unc\attacker\share\planted.dll"));
        }

        [TestMethod]
        public void IsNetworkPathAcceptsLocalPaths()
        {
            Assert.IsFalse(PathUtils.IsNetworkPath(@"C:\Windows\System32\shell32.dll"));
            // The extended-length prefix does not by itself mean the path is remote.
            Assert.IsFalse(PathUtils.IsNetworkPath(@"\\?\C:\Windows\System32\shell32.dll"));
            Assert.IsFalse(PathUtils.IsNetworkPath("shell32.dll"));
            Assert.IsFalse(PathUtils.IsNetworkPath(null));
            Assert.IsFalse(PathUtils.IsNetworkPath("   "));
        }

        [TestMethod]
        public void RegistryPermissionsAreUserWritableWhenInteractiveMaySetValue()
        {
            var permissions = new Dictionary<string, List<string>>
            {
                { "NT AUTHORITY\\SYSTEM", new List<string> { "Allow:FullControl" } },
                { "NT AUTHORITY\\INTERACTIVE", new List<string> { "Allow:SetValue", "Allow:CreateSubKey" } },
            };

            Assert.IsTrue(PermissionUtils.IsUserWritable(permissions));
        }

        [TestMethod]
        public void RegistryPermissionsHonorDenyAces()
        {
            var permissions = new Dictionary<string, List<string>>
            {
                { "NT AUTHORITY\\INTERACTIVE", new List<string> { "Allow:SetValue", "Deny:SetValue" } },
            };

            Assert.IsFalse(PermissionUtils.IsUserWritable(permissions));
        }

        [TestMethod]
        public void RegistryPermissionsIgnorePrivilegedPrincipalsAndReadRights()
        {
            Assert.IsFalse(PermissionUtils.IsUserWritable(new Dictionary<string, List<string>>
            {
                { "BUILTIN\\Administrators", new List<string> { "Allow:FullControl" } },
                { "NT AUTHORITY\\SYSTEM", new List<string> { "Allow:FullControl" } },
                { "BUILTIN\\Users", new List<string> { "Allow:ReadKey", "Allow:QueryValues" } },
            }));
        }

        [TestMethod]
        public void RegistryPermissionsWithoutAccessTypePrefixAreReadAsAllow()
        {
            // Databases collected before the access control type was recorded have unprefixed rights.
            Assert.IsTrue(PermissionUtils.IsUserWritable(new Dictionary<string, List<string>>
            {
                { "BUILTIN\\Users", new List<string> { "WriteKey" } },
            }));
        }

        [TestMethod]
        public void EveryoneIsRecognizedByRawSidAndByName()
        {
            Assert.IsTrue(PermissionUtils.IsUnprivilegedPrincipal("S-1-1-0"));
            Assert.IsTrue(PermissionUtils.IsUnprivilegedPrincipal("Everyone"));
            Assert.IsTrue(PermissionUtils.IsUnprivilegedPrincipal("NT AUTHORITY\\INTERACTIVE"));
            Assert.IsTrue(PermissionUtils.IsUnprivilegedPrincipal("BUILTIN\\Users"));
            Assert.IsTrue(PermissionUtils.IsUnprivilegedPrincipal("S-1-5-32-545"));
            Assert.IsFalse(PermissionUtils.IsUnprivilegedPrincipal("NT AUTHORITY\\SYSTEM"));
            Assert.IsFalse(PermissionUtils.IsUnprivilegedPrincipal("BUILTIN\\Administrators"));
            Assert.IsFalse(PermissionUtils.IsUnprivilegedPrincipal(null));
        }

        [TestMethod]
        public void FilePermissionsAreUserWritableWhenUsersMayCreateFiles()
        {
            Assert.IsTrue(PermissionUtils.IsUserWritable(new Dictionary<string, string>
            {
                { "BUILTIN\\Users", "CreateFiles,AppendData,ReadAndExecute" },
            }));

            Assert.IsFalse(PermissionUtils.IsUserWritable(new Dictionary<string, string>
            {
                { "BUILTIN\\Users", "ReadAndExecute,Synchronize" },
            }));
        }

        [TestMethod]
        public void NearestExistingParentWalksUpToTheDirectoryThatWouldReceiveTheFile()
        {
            var root = Directory.CreateTempSubdirectory("asa-loadpoint-").FullName;

            try
            {
                var missing = Path.Combine(root, "Contoso", "Nested", "planted.dll");

                Assert.AreEqual(root, PermissionUtils.NearestExistingParent(missing));
            }
            finally
            {
                Directory.Delete(root, true);
            }
        }

        [TestMethod]
        public void NearestExistingParentReturnsNullForEmptyInput()
        {
            Assert.IsNull(PermissionUtils.NearestExistingParent(null));
            Assert.IsNull(PermissionUtils.NearestExistingParent("   "));
        }

        private const string TestVariable = "ASA_LOADPOINT_TEST_DIR";
    }
}
