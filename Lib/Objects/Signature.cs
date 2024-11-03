// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Newtonsoft.Json;
using PeNet.Header.Authenticode;
using ProtoBuf;
using System;
using System.Security.Cryptography.X509Certificates;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [ProtoContract]
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

        [ProtoMember(1)]
        public bool IsAuthenticodeValid { get; set; }
        [ProtoMember(2)]
        public string? SignedHash { get; set; }
        [ProtoMember(3)]
        public string? SignerSerialNumber { get; set; }
        [ProtoMember(4)]
        public SerializableCertificate? SigningCertificate { get; set; }
    }
}