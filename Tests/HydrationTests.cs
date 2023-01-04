using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics;
using KellermanSoftware.CompareNetObjects;
using MessagePack;

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
            var dehydrated = SerializationUtils.Dehydrate(co);
            var rehydrated = SerializationUtils.Hydrate(dehydrated, RESULT_TYPE.CERTIFICATE);
            Assert.IsTrue(compareLogic.Compare(co, rehydrated).AreEqual);
        }

        [TestMethod]
        public void TestSerializeAndDeserializeComObject()
        {
            var com = new ComObject(new RegistryObject("Test Key", Microsoft.Win32.RegistryView.Default));
            var compareLogic = new CompareLogic();
            var dehydrated = SerializationUtils.Dehydrate(com);
            var rehydrated = SerializationUtils.Hydrate(dehydrated, RESULT_TYPE.COM);
            Assert.IsTrue(compareLogic.Compare(com, rehydrated).AreEqual);
        }

        [TestMethod]
        public void TestSerializeAndDeserializeCryptographicKeyObject()
        {
            var cko = new CryptographicKeyObject("Disk", Tpm2Lib.TpmAlgId.Rsa) { RsaDetails = new RsaKeyDetails() };
            var compareLogic = new CompareLogic();
            var dehydrated = SerializationUtils.Dehydrate(cko);
            var rehydrated = SerializationUtils.Hydrate(dehydrated, RESULT_TYPE.KEY);
            Assert.IsTrue(compareLogic.Compare(cko, rehydrated).AreEqual);
        }

        [TestMethod]
        public void TestSerializeAndDeserializeDriverObject()
        {
            var DriverName = "MyName";
            var driverObject = new DriverObject(DriverName);
            var compareLogic = new CompareLogic();
            var dehydrated = SerializationUtils.Dehydrate(driverObject);
            var rehydrated = SerializationUtils.Hydrate(dehydrated, RESULT_TYPE.DRIVER);
            Assert.IsTrue(compareLogic.Compare(driverObject, rehydrated).AreEqual);
        }

        [TestMethod]
        public void TestSerializeAndDeserializeEventLogObject()
        {
            var elo = new EventLogObject("Disk");
            var compareLogic = new CompareLogic();
            var dehydrated = SerializationUtils.Dehydrate(elo);
            var rehydrated = SerializationUtils.Hydrate(dehydrated, RESULT_TYPE.LOG);
            Assert.IsTrue(compareLogic.Compare(elo, rehydrated).AreEqual);
        }

        [TestMethod]
        public void TestSerializeAndDeserializeFileSystemObject()
        {
            var fso = new FileSystemObject("Test");
            var compare = new CompareLogic();
            var dehydrated = SerializationUtils.Dehydrate(fso);
            var hydrated = SerializationUtils.Hydrate(dehydrated, RESULT_TYPE.FILE);
            Assert.IsTrue(compare.Compare(fso, hydrated).AreEqual);
        }

        [TestMethod]
        public void TestSerializeAndDeserializeFirewallObject()
        {
            var fwo = new FirewallObject("Test");
            var compareLogic = new CompareLogic();
            var dehydrated = SerializationUtils.Dehydrate(fwo);
            var rehydrated = SerializationUtils.Hydrate(dehydrated, RESULT_TYPE.FIREWALL);
            Assert.IsTrue(compareLogic.Compare(fwo, rehydrated).AreEqual);
        }

        [TestMethod]
        public void TestSerializeAndDeserializeGroupAccountObject()
        {
            var ugo = new GroupAccountObject("TestGroup");
            var compareLogic = new CompareLogic();
            var dehydrated = SerializationUtils.Dehydrate(ugo);
            var rehydrated = SerializationUtils.Hydrate(dehydrated, RESULT_TYPE.GROUP);
            Assert.IsTrue(compareLogic.Compare(ugo, rehydrated).AreEqual);
        }

        [TestMethod]
        public void TestSerializeAndDeserializeOpenPortObject()
        {
            var opo = new OpenPortObject(1024, TRANSPORT.TCP);
            var compareLogic = new CompareLogic();
            var dehydrated = SerializationUtils.Dehydrate(opo);
            var rehydrated = SerializationUtils.Hydrate(dehydrated, RESULT_TYPE.PORT);
            Assert.IsTrue(compareLogic.Compare(opo, rehydrated).AreEqual);
        }

        [TestMethod]
        public void TestSerializeAndDeserializeProcessObject()
        {
            var po = ProcessObject.FromProcess(Process.GetCurrentProcess());
            var compareLogic = new CompareLogic();
            var dehydrated = SerializationUtils.Dehydrate(po);
            var rehydrated = SerializationUtils.Hydrate(dehydrated, RESULT_TYPE.PROCESS);
            Assert.IsTrue(compareLogic.Compare(po, rehydrated).AreEqual);
        }

        [TestMethod]
        public void TestSerializeAndDeserializeRegistryObject()
        {
            var ro = new RegistryObject("Test Key", Microsoft.Win32.RegistryView.Default);
            var compare = new CompareLogic();
            var dehydrated = SerializationUtils.Dehydrate(ro);
            var hydrated = SerializationUtils.Hydrate(dehydrated, RESULT_TYPE.REGISTRY);
            var compared = compare.Compare(ro, hydrated);
            Assert.IsTrue(compared.AreEqual);
        }

        [TestMethod]
        public void TestSerializeAndDeserializeServiceObject()
        {
            var so = new ServiceObject("TestService");
            var compareLogic = new CompareLogic();
            var dehydrated = SerializationUtils.Dehydrate(so);
            var rehydrated = SerializationUtils.Hydrate(dehydrated, RESULT_TYPE.SERVICE);
            Assert.IsTrue(compareLogic.Compare(so, rehydrated).AreEqual);
        }

        [TestMethod]
        public void TestSerializeAndDeserializeTpmObject()
        {
            var tpmo = new TpmObject("TestLocation");
            var compareLogic = new CompareLogic();
            var dehydrated = SerializationUtils.Dehydrate(tpmo);
            var rehydrated = SerializationUtils.Hydrate(dehydrated, RESULT_TYPE.TPM);
            Assert.IsTrue(compareLogic.Compare(tpmo, rehydrated).AreEqual);        
        }

        [TestMethod]
        public void TestSerializeAndDeserializeUserAccountObject()
        {
            var uao = new UserAccountObject("TestUser");
            var compareLogic = new CompareLogic();
            var dehydrated = SerializationUtils.Dehydrate(uao);
            var rehydrated = SerializationUtils.Hydrate(dehydrated, RESULT_TYPE.USER);
            Assert.IsTrue(compareLogic.Compare(uao, rehydrated).AreEqual);
        }
    }
}