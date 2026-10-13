// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Newtonsoft.Json;
using PeNet.Header.Authenticode;
using System;
using System.Security.Cryptography.X509Certificates;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    public class Signature
    {
        public Signature(AuthenticodeInfo authenticodeInfo)
        {
            if (authenticodeInfo != null)
            {
                IsAuthenticodeValid = authenticodeInfo.IsAuthenticodeValid;
                if (authenticodeInfo.SignedHash is byte[] hash)
                {
                    SignedHash = Convert.ToBase64String(hash);
                }
                SignerSerialNumber = authenticodeInfo.SignerSerialNumber;
                if (authenticodeInfo.SigningCertificate is X509Certificate2 cert)
                {
                    SigningCertificate = new SerializableCertificate(cert);
                }
            }
            else
            {
                IsAuthenticodeValid = false;
            }
        }

        /// <summary>
        ///     This constructor is for deserialization.
        /// </summary>
        /// <param name="IsAuthenticodeValid"> </param>
        [JsonConstructor]
        public Signature()
        {
        }

        /// <summary>
        ///     True when the signature carries a signing time which falls inside the signing
        ///     certificate's validity period. A binary that was correctly signed and timestamped stays
        ///     valid here even after its certificate expires. False when the signing time could not be
        ///     determined, so callers that need to distinguish "signed outside validity" from "signing
        ///     time unknown" should also inspect <see cref="SigningTime"/>.
        /// </summary>
        public bool IsTimeValid
        {
            get
            {
                if (SigningCertificate is SerializableCertificate certificate && SigningTime is DateTime signingTime)
                {
                    // Signing times are recovered as UTC while certificate validity comes back from
                    // X509Certificate2 as local time, so both sides are normalized before comparing.
                    var signedAtUtc = signingTime.ToUniversalTime();
                    return signedAtUtc >= certificate.NotBefore.ToUniversalTime() &&
                           signedAtUtc <= certificate.NotAfter.ToUniversalTime();
                }
                return false;
            }
        }

        public bool IsAuthenticodeValid { get; set; }
        public string? SignedHash { get; set; }
        public string? SignerSerialNumber { get; set; }
        public SerializableCertificate? SigningCertificate { get; set; }

        /// <summary>
        ///     The time the binary was signed, recovered from the Authenticode timestamp when one is
        ///     present. Null when the signature is absent or carries no recoverable timestamp.
        /// </summary>
        public DateTime? SigningTime { get; set; }
    }
}
