// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Newtonsoft.Json;
using PeNet.Header.Authenticode;
using System;
using System.Security.Cryptography.X509Certificates;
using MessagePack;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [MessagePackObject]
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

        [IgnoreMember]
        public bool IsTimeValid
        {
            get
            {
                if (SigningCertificate != null)
                {
                    return DateTime.Now > SigningCertificate.NotBefore && DateTime.Now < SigningCertificate.NotAfter;
                }
                return false;
            }
        }

        [Key(0)]
        public bool IsAuthenticodeValid { get; set; }
        [Key(1)]
        public string? SignedHash { get; set; }
        [Key(2)]
        public string? SignerSerialNumber { get; set; }
        [Key(3)]
        public SerializableCertificate? SigningCertificate { get; set; }
    }
}