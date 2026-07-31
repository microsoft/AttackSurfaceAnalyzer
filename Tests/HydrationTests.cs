using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Tests
{
    [TestClass, TestCategory("PipelineSafeTests")]
    public class HydrationTests
    {
        [ClassInitialize]
        public static void ClassSetup(TestContext _)
        {
            Logger.Setup(false, true);
            Strings.Setup();
        }

        [TestMethod]
        public void TestSerializeAndDeserializeCertificateObject()
        {
            var co = new CertificateObject("StoreLocation", "StoreName", new SerializableCertificate("Thumbprint", "Subject", "PublicKey", DateTime.Now.AddYears(1), DateTime.Now, "Issuer", "SerialNumber", "CertHashString", "Pkcs7"));

            if (JsonUtils.Hydrate(JsonUtils.Dehydrate(co), RESULT_TYPE.CERTIFICATE) is CertificateObject co2)
            {
                Assert.IsTrue(co.RowKey.Equals(co2.RowKey));
                Assert.IsTrue(co.Certificate.Thumbprint.Equals(co2.Certificate.Thumbprint));
            }
            else
            {
                Assert.Fail();
            }
        }

        [TestMethod]
        public void TestSerializeAndDeserializeComObject()
        {
            var com = new ComObject(new RegistryObject("Test Key", Microsoft.Win32.RegistryView.Default));

            Assert.IsTrue(com.RowKey.Equals(JsonUtils.Hydrate(JsonUtils.Dehydrate(com), RESULT_TYPE.COM)?.RowKey));
        }

        [TestMethod]
        public void TestSerializeAndDeserializeCryptographicKeyObject()
        {
            var cko = new CryptographicKeyObject("Disk", Tpm2Lib.TpmAlgId.Rsa) { RsaDetails = new RsaKeyDetails() };

            var hydrated = JsonUtils.Hydrate(JsonUtils.Dehydrate(cko), RESULT_TYPE.KEY);
            Assert.IsTrue(cko.RowKey.Equals(hydrated.RowKey));
        }

        public void TestSerializeAndDeserializeDriverObject()
        {
            var DriverName = "MyName";
            var driverObject = new DriverObject(DriverName);
            var serialized = JsonUtils.Dehydrate(driverObject);
            var rehydrated = JsonUtils.Hydrate(serialized, RESULT_TYPE.DRIVER);
            Assert.IsTrue(serialized == JsonUtils.Dehydrate(rehydrated));
            Assert.IsTrue(rehydrated.Identity == DriverName);
        }

        [TestMethod]
        public void TestSerializeAndDeserializeEventLogObject()
        {
            var elo = new EventLogObject("Disk");

            Assert.IsTrue(elo.RowKey.Equals(JsonUtils.Hydrate(JsonUtils.Dehydrate(elo), RESULT_TYPE.LOG)?.RowKey));
        }

        [TestMethod]
        public void TestSerializeAndDeserializeFileSystemObject()
        {
            var fso = new FileSystemObject("Test");

            Assert.IsTrue(fso.RowKey.Equals(JsonUtils.Hydrate(JsonUtils.Dehydrate(fso), RESULT_TYPE.FILE)?.RowKey));
        }

        [TestMethod]
        public void TestSerializeAndDeserializeFirewallObject()
        {
            var fwo = new FirewallObject("Test");

            Assert.IsTrue(fwo.RowKey.Equals(JsonUtils.Hydrate(JsonUtils.Dehydrate(fwo), RESULT_TYPE.FIREWALL)?.RowKey));
        }

        [TestMethod]
        public void TestSerializeAndDeserializeGroupAccountObject()
        {
            var ugo = new GroupAccountObject("TestGroup");

            Assert.IsTrue(ugo.RowKey.Equals(JsonUtils.Hydrate(JsonUtils.Dehydrate(ugo), RESULT_TYPE.GROUP)?.RowKey));
        }

        [TestMethod]
        public void TestSerializeAndDeserializeOpenPortObject()
        {
            var opo = new OpenPortObject(1024, TRANSPORT.TCP);

            Assert.IsTrue(opo.RowKey.Equals(JsonUtils.Hydrate(JsonUtils.Dehydrate(opo), RESULT_TYPE.PORT)?.RowKey));
        }

        [TestMethod]
        public void TestSerializeAndDeserializeProcessObject()
        {
            var po = ProcessObject.FromProcess(Process.GetCurrentProcess());
            var serialized = JsonUtils.Dehydrate(po);
            Assert.IsTrue(serialized == JsonUtils.Dehydrate(JsonUtils.Hydrate(serialized, RESULT_TYPE.PROCESS)));
        }

        [TestMethod]
        public void TestSerializeAndDeserializeRegistryObject()
        {
            var ro = new RegistryObject("Test Key", Microsoft.Win32.RegistryView.Default);

            Assert.IsTrue(ro.RowKey.Equals(JsonUtils.Hydrate(JsonUtils.Dehydrate(ro), RESULT_TYPE.REGISTRY)?.RowKey));
        }

        [TestMethod]
        public void TestSerializeAndDeserializeRegistryObjectReferences()
        {
            var ro = new RegistryObject("Test Key", Microsoft.Win32.RegistryView.Default)
            {
                PermissionsString = "O:BAG:SYD:(A;;KA;;;IU)",
                ReferencedPaths = { @"C:\ProgramData\Contoso\plugin.dll" },
                ReferencedClsids = { "{E9F83CF2-E0C0-4CA7-AF01-E90C70BEF496}" },
            };
            ro.Permissions.Add("NT AUTHORITY\\INTERACTIVE", new System.Collections.Generic.List<string> { "Allow:SetValue" });

            if (JsonUtils.Hydrate(JsonUtils.Dehydrate(ro), RESULT_TYPE.REGISTRY) is RegistryObject ro2)
            {
                Assert.AreEqual(ro.RowKey, ro2.RowKey);
                Assert.AreEqual(ro.PermissionsString, ro2.PermissionsString);
                CollectionAssert.AreEqual(ro.ReferencedPaths, ro2.ReferencedPaths);
                CollectionAssert.AreEqual(ro.ReferencedClsids, ro2.ReferencedClsids);
                CollectionAssert.AreEqual(ro.Permissions["NT AUTHORITY\\INTERACTIVE"], ro2.Permissions["NT AUTHORITY\\INTERACTIVE"]);
            }
            else
            {
                Assert.Fail();
            }
        }

        [TestMethod]
        public void TestSerializeAndDeserializeLoadPointObject()
        {
            var sourceKey = new RegistryObject(@"HKEY_LOCAL_MACHINE\SOFTWARE\Test", Microsoft.Win32.RegistryView.Registry64);
            sourceKey.Permissions.Add("NT AUTHORITY\\INTERACTIVE", new System.Collections.Generic.List<string> { "Allow:SetValue" });

            var lp = new LoadPointObject("StaticPluginMap", sourceKey)
            {
                SourceValueName = "StaticPluginMap",
                SourceValueData = "1:{E9F83CF2-E0C0-4CA7-AF01-E90C70BEF496}",
                SourceKeyUserWritable = true,
                TargetClsid = "{E9F83CF2-E0C0-4CA7-AF01-E90C70BEF496}",
                TargetPath = @"C:\ProgramData\CrossDevice\CrossDevice.Streaming.Source.dll",
                TargetExists = false,
                TargetUserWritable = true,
                TargetAclSource = "NearestExistingParent",
                NearestExistingParentPath = @"C:\ProgramData",
                View = Microsoft.Win32.RegistryView.Registry64,
                ResolutionChain = { "step one", "step two" },
            };

            if (JsonUtils.Hydrate(JsonUtils.Dehydrate(lp), RESULT_TYPE.LOADPOINT) is LoadPointObject lp2)
            {
                Assert.AreEqual(lp.RowKey, lp2.RowKey);
                Assert.AreEqual(lp.Identity, lp2.Identity);
                Assert.AreEqual(lp.LoadPointType, lp2.LoadPointType);
                Assert.AreEqual(lp.SourceKeyUserWritable, lp2.SourceKeyUserWritable);
                Assert.AreEqual(lp.TargetUserWritable, lp2.TargetUserWritable);
                Assert.AreEqual(lp.TargetExists, lp2.TargetExists);
                Assert.AreEqual(lp.TargetAclSource, lp2.TargetAclSource);
                Assert.AreEqual(lp.TargetPath, lp2.TargetPath);
                Assert.AreEqual(lp.NearestExistingParentPath, lp2.NearestExistingParentPath);
                Assert.AreEqual(lp.SourceKey.Key, lp2.SourceKey.Key);
                CollectionAssert.AreEqual(lp.ResolutionChain, lp2.ResolutionChain);
            }
            else
            {
                Assert.Fail();
            }
        }

        [TestMethod]
        public void TestSerializeAndDeserializeServiceObject()
        {
            var so = new ServiceObject("TestService");

            Assert.IsTrue(so.RowKey.Equals(JsonUtils.Hydrate(JsonUtils.Dehydrate(so), RESULT_TYPE.SERVICE)?.RowKey));
        }

        [TestMethod]
        public void TestSerializeAndDeserializeTpmObject()
        {
            var tpmo = new TpmObject("TestLocation");

            Assert.IsTrue(tpmo.RowKey.Equals(JsonUtils.Hydrate(JsonUtils.Dehydrate(tpmo), RESULT_TYPE.TPM)?.RowKey));
        }

        [TestMethod]
        public void TestSerializeAndDeserializeUserAccountObject()
        {
            var uao = new UserAccountObject("TestUser");

            Assert.IsTrue(uao.RowKey.Equals(JsonUtils.Hydrate(JsonUtils.Dehydrate(uao), RESULT_TYPE.USER)?.RowKey));
        }
    }
}