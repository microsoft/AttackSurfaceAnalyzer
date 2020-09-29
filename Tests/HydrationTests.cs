using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Tests
{
    [TestClass]
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