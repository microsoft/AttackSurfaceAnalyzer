// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Collectors;
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PeNet;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.Pkcs;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Tests
{
    [TestClass, TestCategory("PipelineSafeTests")]
    public class SignatureTests
    {
        private const string OutsideValidityRule = "Binaries signed outside certificate validity period";
        private const string UndeterminableTimeRule = "Binaries with an undeterminable signing time";

        /// <summary>
        ///     A binary timestamped with the legacy Authenticode format, where the signing time lives in a
        ///     PKCS#9 countersignature.
        /// </summary>
        private static readonly string LegacyTimestampedBinary = Path.Combine(AppContext.BaseDirectory, "TpmSim", "vcruntime140d.dll");

        /// <summary>
        ///     An unsigned binary.
        /// </summary>
        private static readonly string UnsignedBinary = Path.Combine(AppContext.BaseDirectory, "TpmSim", "Simulator.exe");

        /// <summary>
        ///     Assemblies shipped alongside the tests which are timestamped with the modern RFC 3161 format.
        ///     Any of these exercises the RFC 3161 code path; the first usable one is chosen at runtime so a
        ///     package update cannot silently remove coverage.
        /// </summary>
        private static readonly string[] Rfc3161TimestampedCandidates =
        {
            "Microsoft.Data.Sqlite.dll",
            "Newtonsoft.Json.dll",
            "Microsoft.CodeAnalysis.dll"
        };

        [ClassInitialize]
        public static void ClassSetup(TestContext _)
        {
            Logger.Setup(false, true);
            Strings.Setup();
        }

        #region IsTimeValid unit tests

        [TestMethod]
        public void IsTimeValid_SignedDuringCertValidity_ReturnsTrue()
        {
            var sig = MakeSignature(signingTime: new DateTime(2023, 6, 15),
                                    notBefore: new DateTime(2020, 1, 1),
                                    notAfter: new DateTime(2025, 12, 31));
            Assert.IsTrue(sig.IsTimeValid);
        }

        [TestMethod]
        public void IsTimeValid_SignedAfterCertExpiry_ReturnsFalse()
        {
            var sig = MakeSignature(signingTime: new DateTime(2023, 6, 15),
                                    notBefore: new DateTime(2020, 1, 1),
                                    notAfter: new DateTime(2022, 12, 31));
            Assert.IsFalse(sig.IsTimeValid);
        }

        [TestMethod]
        public void IsTimeValid_SignedBeforeCertNotBefore_ReturnsFalse()
        {
            var sig = MakeSignature(signingTime: new DateTime(2019, 6, 15),
                                    notBefore: new DateTime(2020, 1, 1),
                                    notAfter: new DateTime(2025, 12, 31));
            Assert.IsFalse(sig.IsTimeValid);
        }

        [TestMethod]
        public void IsTimeValid_NullSigningTime_ReturnsFalse()
        {
            var sig = MakeSignature(signingTime: null,
                                    notBefore: new DateTime(2020, 1, 1),
                                    notAfter: new DateTime(2025, 12, 31));
            Assert.IsFalse(sig.IsTimeValid);
        }

        [TestMethod]
        public void IsTimeValid_NullSigningCertificate_ReturnsFalse()
        {
            var sig = new Signature() { SigningCertificate = null, SigningTime = new DateTime(2023, 6, 15) };
            Assert.IsFalse(sig.IsTimeValid);
        }

        [TestMethod]
        public void IsTimeValid_CertExpiredNow_ButSignedDuringValidity_ReturnsTrue()
        {
            // This is the key scenario: cert is currently expired, but was valid when signing occurred
            var sig = MakeSignature(signingTime: new DateTime(2019, 6, 15),
                                    notBefore: new DateTime(2018, 1, 1),
                                    notAfter: new DateTime(2020, 12, 31));
            Assert.IsTrue(sig.IsTimeValid);
        }

        [TestMethod]
        public void IsTimeValid_SignedExactlyAtNotBefore_ReturnsTrue()
        {
            var notBefore = new DateTime(2020, 1, 1);
            var sig = MakeSignature(signingTime: notBefore, notBefore: notBefore, notAfter: new DateTime(2025, 12, 31));
            Assert.IsTrue(sig.IsTimeValid);
        }

        [TestMethod]
        public void IsTimeValid_SignedExactlyAtNotAfter_ReturnsTrue()
        {
            var notAfter = new DateTime(2025, 12, 31);
            var sig = MakeSignature(signingTime: notAfter, notBefore: new DateTime(2020, 1, 1), notAfter: notAfter);
            Assert.IsTrue(sig.IsTimeValid);
        }

        [TestMethod]
        public void IsTimeValid_SameInstantExpressedInDifferentKinds_AgreesOnValidity()
        {
            var notBeforeUtc = new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var notAfterUtc = new DateTime(2021, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var signingTimeUtc = new DateTime(2020, 6, 1, 0, 0, 0, DateTimeKind.Utc);

            var allUtc = MakeSignature(signingTimeUtc, notBeforeUtc, notAfterUtc);
            var allLocal = MakeSignature(signingTimeUtc.ToLocalTime(), notBeforeUtc.ToLocalTime(), notAfterUtc.ToLocalTime());
            // Signing times are recovered as UTC while certificate validity comes back as local time,
            // which is the combination produced by a real collection.
            var mixed = MakeSignature(signingTimeUtc, notBeforeUtc.ToLocalTime(), notAfterUtc.ToLocalTime());

            Assert.IsTrue(allUtc.IsTimeValid);
            Assert.AreEqual(allUtc.IsTimeValid, allLocal.IsTimeValid, "Validity must not depend on how the times are expressed");
            Assert.AreEqual(allUtc.IsTimeValid, mixed.IsTimeValid, "Validity must not depend on how the times are expressed");
        }

        [TestMethod]
        public void IsTimeValid_UtcSigningTimeAtLocalCertBoundary_ComparesInUtc()
        {
            var notBeforeLocal = new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Local);
            var notAfterLocal = new DateTime(2021, 1, 1, 0, 0, 0, DateTimeKind.Local);

            var atNotAfter = MakeSignature(notAfterLocal.ToUniversalTime(), notBeforeLocal, notAfterLocal);
            Assert.IsTrue(atNotAfter.IsTimeValid, "Signing exactly at NotAfter is inside the validity period");

            var atNotBefore = MakeSignature(notBeforeLocal.ToUniversalTime(), notBeforeLocal, notAfterLocal);
            Assert.IsTrue(atNotBefore.IsTimeValid, "Signing exactly at NotBefore is inside the validity period");

            var pastNotAfter = MakeSignature(notAfterLocal.ToUniversalTime().AddSeconds(1), notBeforeLocal, notAfterLocal);
            Assert.IsFalse(pastNotAfter.IsTimeValid, "Signing one second after NotAfter is outside the validity period");

            var beforeNotBefore = MakeSignature(notBeforeLocal.ToUniversalTime().AddSeconds(-1), notBeforeLocal, notAfterLocal);
            Assert.IsFalse(beforeNotBefore.IsTimeValid, "Signing one second before NotBefore is outside the validity period");
        }

        #endregion

        #region Signing time extraction against real binaries

        [TestMethod]
        public void GetSignatureStatus_LegacyCounterSignedBinary_PopulatesSigningTime()
        {
            var sig = GetSignatureOrInconclusive(LegacyTimestampedBinary);

            Assert.IsTrue(sig.IsAuthenticodeValid, "Known-signed binary should be authenticode valid");
            Assert.IsNotNull(sig.SigningTime, "Signed binary should have an extracted SigningTime");
            Assert.AreEqual(DateTimeKind.Utc, sig.SigningTime.Value.Kind, "Signing times are reported in UTC");
            Assert.IsTrue(sig.SigningTime.Value > new DateTime(2000, 1, 1), "SigningTime should be a reasonable date");
            Assert.IsTrue(sig.SigningTime.Value < DateTime.UtcNow, "SigningTime should be in the past");
        }

        [TestMethod]
        public void GetSignatureStatus_LegacyCounterSignedBinary_IsTimeValidReflectsSigningWindow()
        {
            var sig = GetSignatureOrInconclusive(LegacyTimestampedBinary);

            Assert.IsNotNull(sig.SigningTime);
            Assert.IsNotNull(sig.SigningCertificate);
            Assert.IsTrue(sig.IsTimeValid, "A properly timestamped binary should have IsTimeValid = true");
        }

        /// <summary>
        ///     Modern Authenticode signatures carry an RFC 3161 timestamp token instead of a PKCS#9
        ///     countersignature, and the token's authoritative time is the genTime of its encapsulated
        ///     TSTInfo rather than a signingTime attribute. Without support for that shape virtually every
        ///     current Windows binary would report an unknown signing time.
        /// </summary>
        [TestMethod]
        public void GetSignatureStatus_Rfc3161TimestampedBinary_PopulatesSigningTime()
        {
            var path = FindRfc3161TimestampedBinary();
            if (path is null)
            {
                Assert.Inconclusive("No RFC 3161 timestamped binary was found next to the test assembly");
                return;
            }

            Assert.AreEqual(0, CountPkcs9CounterSigners(path),
                $"{Path.GetFileName(path)} must have no PKCS#9 countersignature, otherwise this test does not cover the RFC 3161 path");

            var sig = GetSignatureOrInconclusive(path);

            Assert.IsTrue(sig.IsAuthenticodeValid, "Known-signed binary should be authenticode valid");
            Assert.IsNotNull(sig.SigningTime, "An RFC 3161 timestamped binary should have an extracted SigningTime");
            Assert.AreEqual(DateTimeKind.Utc, sig.SigningTime.Value.Kind, "Signing times are reported in UTC");
            Assert.IsTrue(sig.SigningTime.Value > new DateTime(2000, 1, 1), "SigningTime should be a reasonable date");
            Assert.IsTrue(sig.SigningTime.Value < DateTime.UtcNow, "SigningTime should be in the past");
        }

        [TestMethod]
        public void GetSignatureStatus_Rfc3161TimestampedBinary_IsTimeValidReflectsSigningWindow()
        {
            var path = FindRfc3161TimestampedBinary();
            if (path is null)
            {
                Assert.Inconclusive("No RFC 3161 timestamped binary was found next to the test assembly");
                return;
            }

            var sig = GetSignatureOrInconclusive(path);

            Assert.IsNotNull(sig.SigningTime);
            Assert.IsNotNull(sig.SigningCertificate);
            Assert.IsTrue(sig.IsTimeValid,
                $"Signed at {sig.SigningTime:u}, certificate valid {sig.SigningCertificate.NotBefore:u}..{sig.SigningCertificate.NotAfter:u}");
        }

        [TestMethod]
        public void GetSignatureStatus_WithUnsignedPeFile_HasNullSigningTime()
        {
            if (!File.Exists(UnsignedBinary))
            {
                Assert.Inconclusive("Test binary not found at: " + UnsignedBinary);
                return;
            }

            using var stream = File.OpenRead(UnsignedBinary);
            var sig = WindowsFileSystemUtils.GetSignatureStatus(UnsignedBinary, stream);

            // Unsigned PE should either return null signature or have null SigningTime
            if (sig != null)
            {
                Assert.IsNull(sig.SigningTime, "Unsigned binary should not have a SigningTime");
                Assert.IsFalse(sig.IsTimeValid, "Unsigned binary should have IsTimeValid = false");
            }
        }

        [TestMethod]
        public void GetSignatureStatus_PathAndStreamOverloads_AgreeOnSigningTime()
        {
            var path = FindRfc3161TimestampedBinary() ?? LegacyTimestampedBinary;
            if (!File.Exists(path))
            {
                Assert.Inconclusive("Test binary not found at: " + path);
                return;
            }

            var fromPath = WindowsFileSystemUtils.GetSignatureStatus(path);
            using var stream = File.OpenRead(path);
            var fromStream = WindowsFileSystemUtils.GetSignatureStatus(path, stream);

            Assert.IsNotNull(fromPath);
            Assert.IsNotNull(fromStream);
            Assert.AreEqual(fromPath.SigningTime, fromStream.SigningTime, "Both collection paths must report the same signing time");
        }

        #endregion

        #region Analysis rule tests

        [TestMethod]
        public void AnalysisRules_SignedWithinValidity_IsNotFlagged()
        {
            var rules = AnalyzeFileWith(MakeSignature(signingTime: new DateTime(2019, 6, 15, 0, 0, 0, DateTimeKind.Utc),
                                                      notBefore: new DateTime(2018, 1, 1),
                                                      notAfter: new DateTime(2030, 12, 31)));

            CollectionAssert.DoesNotContain(rules, OutsideValidityRule);
            CollectionAssert.DoesNotContain(rules, UndeterminableTimeRule);
        }

        /// <summary>
        ///     The regression this whole feature exists to prevent: a binary signed and timestamped while
        ///     its certificate was valid must not be reported once that certificate expires.
        /// </summary>
        [TestMethod]
        public void AnalysisRules_CertificateExpiredButSignedWhileValid_IsNotFlagged()
        {
            var rules = AnalyzeFileWith(MakeSignature(signingTime: new DateTime(2019, 6, 15, 0, 0, 0, DateTimeKind.Utc),
                                                      notBefore: new DateTime(2018, 1, 1),
                                                      notAfter: new DateTime(2020, 12, 31)));

            CollectionAssert.DoesNotContain(rules, OutsideValidityRule);
            CollectionAssert.DoesNotContain(rules, UndeterminableTimeRule);
        }

        [TestMethod]
        public void AnalysisRules_SignedAfterCertificateExpiry_FlagsOutsideValidityOnly()
        {
            var rules = AnalyzeFileWith(MakeSignature(signingTime: new DateTime(2023, 6, 15, 0, 0, 0, DateTimeKind.Utc),
                                                      notBefore: new DateTime(2018, 1, 1),
                                                      notAfter: new DateTime(2020, 12, 31)));

            CollectionAssert.Contains(rules, OutsideValidityRule);
            CollectionAssert.DoesNotContain(rules, UndeterminableTimeRule);
        }

        [TestMethod]
        public void AnalysisRules_SignedBeforeCertificateNotBefore_FlagsOutsideValidityOnly()
        {
            var rules = AnalyzeFileWith(MakeSignature(signingTime: new DateTime(2017, 6, 15, 0, 0, 0, DateTimeKind.Utc),
                                                      notBefore: new DateTime(2018, 1, 1),
                                                      notAfter: new DateTime(2020, 12, 31)));

            CollectionAssert.Contains(rules, OutsideValidityRule);
            CollectionAssert.DoesNotContain(rules, UndeterminableTimeRule);
        }

        [TestMethod]
        public void AnalysisRules_UndeterminableSigningTime_FlagsInformationRuleOnly()
        {
            var rules = AnalyzeFileWith(MakeSignature(signingTime: null,
                                                      notBefore: new DateTime(2018, 1, 1),
                                                      notAfter: new DateTime(2020, 12, 31)));

            CollectionAssert.Contains(rules, UndeterminableTimeRule);
            CollectionAssert.DoesNotContain(rules, OutsideValidityRule);
        }

        [TestMethod]
        public void AnalysisRules_UnsignedBinary_IsNotFlagged()
        {
            var rules = AnalyzeFileWith(MakeSignature(signingTime: null,
                                                      notBefore: new DateTime(2018, 1, 1),
                                                      notAfter: new DateTime(2020, 12, 31),
                                                      isAuthenticodeValid: false));

            CollectionAssert.DoesNotContain(rules, OutsideValidityRule);
            CollectionAssert.DoesNotContain(rules, UndeterminableTimeRule);
        }

        [TestMethod]
        public void AnalysisRules_TheTwoSigningTimeRulesHaveDistinctSeverities()
        {
            var rules = RuleFile.LoadEmbeddedFilters().Rules
                .Where(x => x.Name == OutsideValidityRule || x.Name == UndeterminableTimeRule)
                .OfType<AsaRule>()
                .ToList();

            Assert.AreEqual(4, rules.Count, "Both rules should be defined for FILE and FILEMONITOR");
            Assert.IsTrue(rules.Where(x => x.Name == OutsideValidityRule).All(x => x.Flag == ANALYSIS_RESULT_TYPE.WARNING));
            Assert.IsTrue(rules.Where(x => x.Name == UndeterminableTimeRule).All(x => x.Flag == ANALYSIS_RESULT_TYPE.INFORMATION));
        }

        /// <summary>
        ///     Guards against the analysis regressing into flagging ordinary, correctly signed binaries.
        /// </summary>
        [TestMethod]
        public void AnalysisRules_RealTimestampedBinaries_AreNotFlagged()
        {
            var paths = Rfc3161TimestampedCandidates
                .Select(x => Path.Combine(AppContext.BaseDirectory, x))
                .Append(LegacyTimestampedBinary)
                .Where(File.Exists)
                .ToList();

            if (paths.Count == 0)
            {
                Assert.Inconclusive("No signed binaries were found next to the test assembly");
                return;
            }

            foreach (var path in paths)
            {
                var sig = WindowsFileSystemUtils.GetSignatureStatus(path);
                if (sig is null || !sig.IsAuthenticodeValid)
                {
                    continue;
                }

                var rules = AnalyzeFileWith(sig, path);
                CollectionAssert.DoesNotContain(rules, OutsideValidityRule, $"{Path.GetFileName(path)} was signed at {sig.SigningTime:u}");
                CollectionAssert.DoesNotContain(rules, UndeterminableTimeRule, $"{Path.GetFileName(path)} has no recoverable signing time");
            }
        }

        #endregion

        #region Helpers

        private static Signature MakeSignature(DateTime? signingTime, DateTime notBefore, DateTime notAfter, bool isAuthenticodeValid = true)
        {
            return new Signature()
            {
                IsAuthenticodeValid = isAuthenticodeValid,
                SigningTime = signingTime,
                SigningCertificate = new SerializableCertificate(
                    Thumbprint: "thumbprint",
                    Subject: "CN=Test",
                    PublicKey: "key",
                    NotAfter: notAfter,
                    NotBefore: notBefore,
                    Issuer: "CN=Issuer",
                    SerialNumber: "serial",
                    CertHashString: "hash",
                    Pkcs7: "pkcs7")
            };
        }

        private static Signature GetSignatureOrInconclusive(string path)
        {
            if (!File.Exists(path))
            {
                Assert.Inconclusive("Test binary not found at: " + path);
            }

            using var stream = File.OpenRead(path);
            var sig = WindowsFileSystemUtils.GetSignatureStatus(path, stream);
            Assert.IsNotNull(sig, "Should parse a PE file's signature");
            return sig;
        }

        private static List<string> AnalyzeFileWith(Signature signature, string path = @"C:\test\binary.dll")
        {
            var analyzer = new AsaAnalyzer();
            var ruleFile = RuleFile.LoadEmbeddedFilters();
            var fso = new FileSystemObject(path) { SignatureStatus = signature, IsExecutable = true };

            return analyzer.Analyze(ruleFile.Rules, new CompareResult() { Compare = fso })
                .Select(x => x.Name)
                .ToList();
        }

        /// <summary>
        ///     Returns the first assembly next to the test binary which is Authenticode signed with an RFC
        ///     3161 timestamp and no legacy PKCS#9 countersignature, or null when none is available.
        /// </summary>
        private static string? FindRfc3161TimestampedBinary()
        {
            foreach (var candidate in Rfc3161TimestampedCandidates)
            {
                var path = Path.Combine(AppContext.BaseDirectory, candidate);
                if (!File.Exists(path))
                {
                    continue;
                }

                try
                {
                    if (CountPkcs9CounterSigners(path) == 0 && HasWinCertificate(path))
                    {
                        return path;
                    }
                }
                catch (Exception)
                {
                    // Not usable as a fixture, try the next candidate
                }
            }

            return null;
        }

        private static bool HasWinCertificate(string path)
        {
            using var stream = File.OpenRead(path);
            return PeFile.IsPeFile(stream) && new PeFile(stream).WinCertificate is not null;
        }

        private static int CountPkcs9CounterSigners(string path)
        {
            using var stream = File.OpenRead(path);
            var certData = new PeFile(stream).WinCertificate?.BCertificate.ToArray();
            if (certData is null)
            {
                return 0;
            }

            var cms = new SignedCms();
            cms.Decode(certData);
            return cms.SignerInfos.Cast<SignerInfo>().Sum(x => x.CounterSignerInfos.Count);
        }

        #endregion
    }
}
