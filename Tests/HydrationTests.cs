using System;
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests
{
    [TestClass]
    public class HydrationTests
    {
        [ClassInitialize]
        public void ClassSetup()
        {
            Logger.Setup(false, true);
            Utils.Strings.Setup();
            AsaTelemetry.Setup(test: true);
        }

        [TestMethod]
        public void TestSerializeObjects()
        {
            var co = new CertificateObject("StoreLocation", "StoreName", new SerializableCertificate("Thumbprint", "Subject", "PublicKey", DateTime.Now.AddYears(1), DateTime.Now, "Issuer", "SerialNumber", "CertHashString"));

            if(JsonUtils.Hydrate(JsonUtils.Dehydrate(co), RESULT_TYPE.CERTIFICATE) is CertificateObject co2)
            {
                Assert.IsTrue(co.RowKey.Equals(co2.RowKey));
                Assert.IsTrue(co.Certificate.Thumbprint.Equals(co2.Certificate.Thumbprint));
            }
            else
            {
                Assert.Fail();
            }

            var com = new ComObject(new RegistryObject("Test Key", Microsoft.Win32.RegistryView.Default));

            Assert.IsTrue(com.RowKey.Equals(JsonUtils.Hydrate(JsonUtils.Dehydrate(com), RESULT_TYPE.COM)?.RowKey));

            var cko = new CryptographicKeyObject("Disk");

            Assert.IsTrue(cko.RowKey.Equals(JsonUtils.Hydrate(JsonUtils.Dehydrate(cko), RESULT_TYPE.KEY)?.RowKey));

            var elo = new EventLogObject("Disk");

            Assert.IsTrue(elo.RowKey.Equals(JsonUtils.Hydrate(JsonUtils.Dehydrate(elo), RESULT_TYPE.LOG)?.RowKey));

            var fso = new FileSystemObject("Test");

            Assert.IsTrue(fso.RowKey.Equals(JsonUtils.Hydrate(JsonUtils.Dehydrate(fso), RESULT_TYPE.FILE)?.RowKey));

            var fwo = new FirewallObject("Test");

            Assert.IsTrue(fwo.RowKey.Equals(JsonUtils.Hydrate(JsonUtils.Dehydrate(fwo), RESULT_TYPE.FIREWALL)?.RowKey));

            var opo = new OpenPortObject(1024,TRANSPORT.TCP);

            Assert.IsTrue(opo.RowKey.Equals(JsonUtils.Hydrate(JsonUtils.Dehydrate(opo), RESULT_TYPE.PORT)?.RowKey));

            var ro = new RegistryObject("Test Key", Microsoft.Win32.RegistryView.Default);

            Assert.IsTrue(opo.RowKey.Equals(JsonUtils.Hydrate(JsonUtils.Dehydrate(opo), RESULT_TYPE.REGISTRY)?.RowKey));

            var so = new ServiceObject("TestService");

            Assert.IsTrue(so.RowKey.Equals(JsonUtils.Hydrate(JsonUtils.Dehydrate(so), RESULT_TYPE.SERVICE)?.RowKey));

            var tpmo = new TpmObject("TestLocation");

            Assert.IsTrue(tpmo.RowKey.Equals(JsonUtils.Hydrate(JsonUtils.Dehydrate(tpmo), RESULT_TYPE.FILE)?.RowKey));

            var uao = new UserAccountObject("TestUser");

            Assert.IsTrue(uao.RowKey.Equals(JsonUtils.Hydrate(JsonUtils.Dehydrate(uao), RESULT_TYPE.FILE)?.RowKey));

            var ugo = new GroupAccountObject("TestGroup");

            Assert.IsTrue(ugo.RowKey.Equals(JsonUtils.Hydrate(JsonUtils.Dehydrate(ugo), RESULT_TYPE.FILE)?.RowKey));
        }
    }
}
