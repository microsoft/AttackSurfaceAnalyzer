// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Collectors;
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;

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

        [TestMethod]
        public void GetSignatureStatus_WithSignedPeFile_PopulatesSigningTime()
        {
            // vcruntime140d.dll is a signed Microsoft PE binary already in the repo
            var path = Path.Combine(AppContext.BaseDirectory, "TpmSim", "vcruntime140d.dll");
            if (!File.Exists(path))
                Assert.Inconclusive("Test binary not found at: " + path);

            using var stream = File.OpenRead(path);
            var sig = WindowsFileSystemUtils.GetSignatureStatus(path, stream);

            Assert.IsNotNull(sig, "Should parse a PE file's signature");
            Assert.IsNotNull(sig.SigningTime, "Signed binary should have an extracted SigningTime");
            Assert.IsTrue(sig.IsAuthenticodeValid, "Known-signed binary should be authenticode valid");
            // The signing time should be within a reasonable historical range
            Assert.IsTrue(sig.SigningTime.Value > new DateTime(2000, 1, 1), "SigningTime should be a reasonable date");
            Assert.IsTrue(sig.SigningTime.Value < DateTime.UtcNow, "SigningTime should be in the past");
        }

        [TestMethod]
        public void GetSignatureStatus_WithSignedPeFile_IsTimeValidReflectsSigningWindow()
        {
            var path = Path.Combine(AppContext.BaseDirectory, "TpmSim", "vcruntime140d.dll");
            if (!File.Exists(path))
                Assert.Inconclusive("Test binary not found at: " + path);

            using var stream = File.OpenRead(path);
            var sig = WindowsFileSystemUtils.GetSignatureStatus(path, stream);

            Assert.IsNotNull(sig);
            Assert.IsNotNull(sig.SigningTime);
            Assert.IsNotNull(sig.SigningCertificate);
            // The binary was signed while the certificate was valid
            Assert.IsTrue(sig.SigningTime.Value >= sig.SigningCertificate.NotBefore,
                $"SigningTime {sig.SigningTime} should be >= cert NotBefore {sig.SigningCertificate.NotBefore}");
            Assert.IsTrue(sig.SigningTime.Value <= sig.SigningCertificate.NotAfter,
                $"SigningTime {sig.SigningTime} should be <= cert NotAfter {sig.SigningCertificate.NotAfter}");
            Assert.IsTrue(sig.IsTimeValid, "A properly timestamped binary should have IsTimeValid = true");
        }

        [TestMethod]
        public void GetSignatureStatus_WithUnsignedPeFile_HasNullSigningTime()
        {
            var path = Path.Combine(AppContext.BaseDirectory, "TpmSim", "Simulator.exe");
            if (!File.Exists(path))
                Assert.Inconclusive("Test binary not found at: " + path);

            using var stream = File.OpenRead(path);
            var sig = WindowsFileSystemUtils.GetSignatureStatus(path, stream);

            // Unsigned PE should either return null signature or have null SigningTime
            if (sig != null)
            {
                Assert.IsNull(sig.SigningTime, "Unsigned binary should not have a SigningTime");
                Assert.IsFalse(sig.IsTimeValid, "Unsigned binary should have IsTimeValid = false");
            }
        }
    }
}
