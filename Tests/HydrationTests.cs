using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics;
using KellermanSoftware.CompareNetObjects;

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
            var compareLogic = new CompareLogic();
            if (SerializationUtils.Hydrate(SerializationUtils.Dehydrate(co), RESULT_TYPE.CERTIFICATE) is CertificateObject co2)
            {
                Assert.IsTrue(compareLogic.Compare(co, co2).AreEqual);
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

            Assert.IsTrue(com.RowKey.Equals(SerializationUtils.Hydrate(SerializationUtils.Dehydrate(com), RESULT_TYPE.COM)?.RowKey));
        }

        [TestMethod]
        public void TestSerializeAndDeserializeCryptographicKeyObject()
        {
            var cko = new CryptographicKeyObject("Disk", Tpm2Lib.TpmAlgId.Rsa) { RsaDetails = new RsaKeyDetails() };

            var hydrated = SerializationUtils.Hydrate(SerializationUtils.Dehydrate(cko), RESULT_TYPE.KEY);
            Assert.IsTrue(cko.RowKey.Equals(hydrated.RowKey));
        }

        public void TestSerializeAndDeserializeDriverObject()
        {
            var DriverName = "MyName";
            var driverObject = new DriverObject(DriverName);
            var serialized = SerializationUtils.Dehydrate(driverObject);
            var rehydrated = SerializationUtils.Hydrate(serialized, RESULT_TYPE.DRIVER);
            Assert.IsTrue(serialized == SerializationUtils.Dehydrate(rehydrated));
            Assert.IsTrue(rehydrated.Identity == DriverName);
        }

        [TestMethod]
        public void TestSerializeAndDeserializeEventLogObject()
        {
            var elo = new EventLogObject("Disk");

            Assert.IsTrue(elo.RowKey.Equals(SerializationUtils.Hydrate(SerializationUtils.Dehydrate(elo), RESULT_TYPE.LOG)?.RowKey));
        }

        [TestMethod]
        public void TestSerializeAndDeserializeFileSystemObject()
        {
            var fso = new FileSystemObject("Test");

            Assert.IsTrue(fso.RowKey.Equals(SerializationUtils.Hydrate(SerializationUtils.Dehydrate(fso), RESULT_TYPE.FILE)?.RowKey));
        }

        [TestMethod]
        public void TestSerializeAndDeserializeFirewallObject()
        {
            var fwo = new FirewallObject("Test");

            Assert.IsTrue(fwo.RowKey.Equals(SerializationUtils.Hydrate(SerializationUtils.Dehydrate(fwo), RESULT_TYPE.FIREWALL)?.RowKey));
        }

        [TestMethod]
        public void TestSerializeAndDeserializeGroupAccountObject()
        {
            var ugo = new GroupAccountObject("TestGroup");

            Assert.IsTrue(ugo.RowKey.Equals(SerializationUtils.Hydrate(SerializationUtils.Dehydrate(ugo), RESULT_TYPE.GROUP)?.RowKey));
        }

        [TestMethod]
        public void TestSerializeAndDeserializeOpenPortObject()
        {
            var opo = new OpenPortObject(1024, TRANSPORT.TCP);

            Assert.IsTrue(opo.RowKey.Equals(SerializationUtils.Hydrate(SerializationUtils.Dehydrate(opo), RESULT_TYPE.PORT)?.RowKey));
        }

        [TestMethod]
        public void TestSerializeAndDeserializeProcessObject()
        {
            var po = ProcessObject.FromProcess(Process.GetCurrentProcess());
            var serialized = SerializationUtils.Dehydrate(po);
            Assert.IsTrue(serialized == SerializationUtils.Dehydrate(SerializationUtils.Hydrate(serialized, RESULT_TYPE.PROCESS)));
        }

        [TestMethod]
        public void TestSerializeAndDeserializeRegistryObject()
        {
            var ro = new RegistryObject("Test Key", Microsoft.Win32.RegistryView.Default);

            Assert.IsTrue(ro.RowKey.Equals(SerializationUtils.Hydrate(SerializationUtils.Dehydrate(ro), RESULT_TYPE.REGISTRY)?.RowKey));
        }

        [TestMethod]
        public void TestSerializeAndDeserializeServiceObject()
        {
            var so = new ServiceObject("TestService");

            Assert.IsTrue(so.RowKey.Equals(SerializationUtils.Hydrate(SerializationUtils.Dehydrate(so), RESULT_TYPE.SERVICE)?.RowKey));
        }

        [TestMethod]
        public void TestSerializeAndDeserializeTpmObject()
        {
            var tpmo = new TpmObject("TestLocation");

            Assert.IsTrue(tpmo.RowKey.Equals(SerializationUtils.Hydrate(SerializationUtils.Dehydrate(tpmo), RESULT_TYPE.TPM)?.RowKey));
        }

        [TestMethod]
        public void TestSerializeAndDeserializeUserAccountObject()
        {
            var uao = new UserAccountObject("TestUser");

            Assert.IsTrue(uao.RowKey.Equals(SerializationUtils.Hydrate(SerializationUtils.Dehydrate(uao), RESULT_TYPE.USER)?.RowKey));
        }
    }
}