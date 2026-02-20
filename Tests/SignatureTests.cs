// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Tests
{
    [TestClass, TestCategory("PipelineSafeTests")]
    public class SignatureTests
    {
        [TestMethod]
        public void IsTimeValid_SignedDuringCertValidity_ReturnsTrue()
        {
            var sig = new Signature()
            {
                SigningCertificate = new SerializableCertificate(
                    "thumbprint", "CN=Test", "key",
                    new DateTime(2025, 12, 31), // NotAfter
                    new DateTime(2020, 1, 1),   // NotBefore
                    "CN=Issuer", "serial", "hash", "pkcs7"),
                SigningTime = new DateTime(2023, 6, 15) // Signed within validity
            };
            Assert.IsTrue(sig.IsTimeValid);
        }

        [TestMethod]
        public void IsTimeValid_SignedAfterCertExpiry_ReturnsFalse()
        {
            var sig = new Signature()
            {
                SigningCertificate = new SerializableCertificate(
                    "thumbprint", "CN=Test", "key",
                    new DateTime(2022, 12, 31), // NotAfter
                    new DateTime(2020, 1, 1),   // NotBefore
                    "CN=Issuer", "serial", "hash", "pkcs7"),
                SigningTime = new DateTime(2023, 6, 15) // Signed after expiry
            };
            Assert.IsFalse(sig.IsTimeValid);
        }

        [TestMethod]
        public void IsTimeValid_SignedBeforeCertNotBefore_ReturnsFalse()
        {
            var sig = new Signature()
            {
                SigningCertificate = new SerializableCertificate(
                    "thumbprint", "CN=Test", "key",
                    new DateTime(2025, 12, 31), // NotAfter
                    new DateTime(2020, 1, 1),   // NotBefore
                    "CN=Issuer", "serial", "hash", "pkcs7"),
                SigningTime = new DateTime(2019, 6, 15) // Signed before NotBefore
            };
            Assert.IsFalse(sig.IsTimeValid);
        }

        [TestMethod]
        public void IsTimeValid_NullSigningTime_ReturnsFalse()
        {
            var sig = new Signature()
            {
                SigningCertificate = new SerializableCertificate(
                    "thumbprint", "CN=Test", "key",
                    new DateTime(2025, 12, 31),
                    new DateTime(2020, 1, 1),
                    "CN=Issuer", "serial", "hash", "pkcs7"),
                SigningTime = null
            };
            Assert.IsFalse(sig.IsTimeValid);
        }

        [TestMethod]
        public void IsTimeValid_NullSigningCertificate_ReturnsFalse()
        {
            var sig = new Signature()
            {
                SigningCertificate = null,
                SigningTime = new DateTime(2023, 6, 15)
            };
            Assert.IsFalse(sig.IsTimeValid);
        }

        [TestMethod]
        public void IsTimeValid_CertExpiredNow_ButSignedDuringValidity_ReturnsTrue()
        {
            // This is the key scenario: cert is currently expired, but was valid when signing occurred
            var sig = new Signature()
            {
                SigningCertificate = new SerializableCertificate(
                    "thumbprint", "CN=Test", "key",
                    new DateTime(2020, 12, 31), // NotAfter - expired now
                    new DateTime(2018, 1, 1),   // NotBefore
                    "CN=Issuer", "serial", "hash", "pkcs7"),
                SigningTime = new DateTime(2019, 6, 15) // Signed while cert was valid
            };
            Assert.IsTrue(sig.IsTimeValid);
        }

        [TestMethod]
        public void IsTimeValid_SignedExactlyAtNotBefore_ReturnsTrue()
        {
            var notBefore = new DateTime(2020, 1, 1);
            var sig = new Signature()
            {
                SigningCertificate = new SerializableCertificate(
                    "thumbprint", "CN=Test", "key",
                    new DateTime(2025, 12, 31),
                    notBefore,
                    "CN=Issuer", "serial", "hash", "pkcs7"),
                SigningTime = notBefore // Signed exactly at NotBefore boundary
            };
            Assert.IsTrue(sig.IsTimeValid);
        }

        [TestMethod]
        public void IsTimeValid_SignedExactlyAtNotAfter_ReturnsTrue()
        {
            var notAfter = new DateTime(2025, 12, 31);
            var sig = new Signature()
            {
                SigningCertificate = new SerializableCertificate(
                    "thumbprint", "CN=Test", "key",
                    notAfter,
                    new DateTime(2020, 1, 1),
                    "CN=Issuer", "serial", "hash", "pkcs7"),
                SigningTime = notAfter // Signed exactly at NotAfter boundary
            };
            Assert.IsTrue(sig.IsTimeValid);
        }
    }
}
