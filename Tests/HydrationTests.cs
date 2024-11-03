using KellermanSoftware.CompareNetObjects;
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using ProtoBuf;
using ProtoBuf.Meta;
using System;
using System.Diagnostics;
using Tpm2Lib;
using System.Linq;

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

        /// <summary>
        /// Check that all Public Properties of the objects are Equal
        /// </summary>
        /// <param name="objectType"></param>
        /// <param name="obj1"></param>
        /// <param name="obj2"></param>
        /// <returns></returns>
        private bool AreAllPropsEqual(Type objectType, object obj1, object obj2)
        {
            foreach (var prop in objectType.GetProperties(System.Reflection.BindingFlags.Public))
            {
                var val1 = prop.GetValue(obj1);
                var val2 = prop.GetValue(obj2);
                if (prop.GetType().IsSubclassOf(typeof(CollectObject)))
                {
                    AreAllPropsEqual(prop.GetType(), val1, val2);
                }
                else if (prop.GetType().Equals(typeof(byte[])))
                {
                    Assert.IsTrue(((byte[])val1).SequenceEqual((byte[])val2));
                }
                else
                {
                    Assert.AreEqual(prop.GetValue(obj1), prop.GetValue(obj2));
                }
            }
            return true;
        }

        /// <summary>
        /// Validate that an object survives serialization and deserialization
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="one"></param>
        /// <param name="resultType"></param>
        private void ValidateHydrateDehydrateEquality<T>(T one, RESULT_TYPE resultType) where T : CollectObject
        {
            // Check by Serializing and Deserializing using our own util
            if (ProtoBufUtils.Hydrate(ProtoBufUtils.Dehydrate(one), resultType) is T two)
            {
                Assert.IsTrue(AreAllPropsEqual(one.GetType(), one, two));
            }
            else
            {
                Assert.Fail();
            }
            // Check with cloning
            var copy = Serializer.DeepClone(one);
            Assert.IsTrue(AreAllPropsEqual(one.GetType(), one, copy));
        }

        [TestMethod]
        public void TestSerializeAndDeserializeCertificateObject()
        {
            var comparator = new CompareLogic();

            var co = new CertificateObject("StoreLocation", "StoreName", new SerializableCertificate("Thumbprint", "Subject", "PublicKey", DateTime.Now.AddYears(1), DateTime.Now, "Issuer", "SerialNumber", "CertHashString", "Pkcs7"));
            ValidateHydrateDehydrateEquality(co, RESULT_TYPE.CERTIFICATE);
        }

        [TestMethod]
        public void TestSerializeAndDeserializeComObject()
        {
            var com = new ComObject(new RegistryObject("Test Key", Microsoft.Win32.RegistryView.Default));
            ValidateHydrateDehydrateEquality(com, RESULT_TYPE.COM);
        }

        [TestMethod]
        public void TestSerializeAndDeserializeCryptographicKeyObject()
        {
            var cko = new CryptographicKeyObject("Disk", Tpm2Lib.TpmAlgId.Rsa) { RsaDetails = new RsaKeyDetails() };
            ValidateHydrateDehydrateEquality(cko, RESULT_TYPE.KEY);
        }

        public void TestSerializeAndDeserializeDriverObject()
        {
            var DriverName = "MyName";
            var driverObject = new DriverObject(DriverName);
            ValidateHydrateDehydrateEquality(driverObject, RESULT_TYPE.DRIVER);
        }

        [TestMethod]
        public void TestSerializeAndDeserializeEventLogObject()
        {
            var elo = new EventLogObject("Disk");
            ValidateHydrateDehydrateEquality(elo, RESULT_TYPE.LOG);
        }

        [TestMethod]
        public void TestSerializeAndDeserializeFileSystemObject()
        {
            var fso = new FileSystemObject("Test");
            ValidateHydrateDehydrateEquality(fso, RESULT_TYPE.FILE);
        }

        [TestMethod]
        public void TestSerializeAndDeserializeFirewallObject()
        {
            var fwo = new FirewallObject("Test");
            ValidateHydrateDehydrateEquality(fwo, RESULT_TYPE.FIREWALL);
        }

        [TestMethod]
        public void TestSerializeAndDeserializeGroupAccountObject()
        {
            var ugo = new GroupAccountObject("TestGroup");
            ValidateHydrateDehydrateEquality(ugo, RESULT_TYPE.GROUP);
        }

        [TestMethod]
        public void TestSerializeAndDeserializeOpenPortObject()
        {
            var opo = new OpenPortObject(1024, TRANSPORT.TCP);
            ValidateHydrateDehydrateEquality(opo, RESULT_TYPE.PORT);
        }

        [TestMethod]
        public void TestSerializeAndDeserializeProcessObject()
        {
            var po = ProcessObject.FromProcess(Process.GetCurrentProcess());
            ValidateHydrateDehydrateEquality(po, RESULT_TYPE.PROCESS);
        }

        [TestMethod]
        public void TestSerializeAndDeserializeRegistryObject()
        {
            var ro = new RegistryObject("Test Key", Microsoft.Win32.RegistryView.Default);
            ValidateHydrateDehydrateEquality(ro, RESULT_TYPE.REGISTRY);
        }

        [TestMethod]
        public void TestSerializeAndDeserializeServiceObject()
        {
            var so = new ServiceObject("TestService");
            ValidateHydrateDehydrateEquality(so, RESULT_TYPE.SERVICE);
        }

        [TestMethod]
        public void TestSerializeAndDeserializeTpmObject()
        {
            var tpmo = new TpmObject("TestLocation");
            ValidateHydrateDehydrateEquality(tpmo, RESULT_TYPE.TPM);
        }

        [TestMethod]
        public void TestSerializeAndDeserializeUserAccountObject()
        {
            var uao = new UserAccountObject("TestUser");
            ValidateHydrateDehydrateEquality(uao, RESULT_TYPE.USER);
        }
    }
}