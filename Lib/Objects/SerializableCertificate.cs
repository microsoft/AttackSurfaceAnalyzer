// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Newtonsoft.Json;
using ProtoBuf;
using System;
using System.Security.Cryptography.X509Certificates;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [ProtoContract]
    public class SerializableCertificate
    {
        public SerializableCertificate(X509Certificate2 certificate)
        {
            Thumbprint = certificate?.Thumbprint ?? throw new ArgumentNullException(nameof(certificate));
            Subject = certificate.Subject;
            PublicKey = certificate.PublicKey.EncodedKeyValue.Format(true);
            NotAfter = certificate.NotAfter;
            NotBefore = certificate.NotBefore;
            Issuer = certificate.Issuer;
            SerialNumber = certificate.SerialNumber;
            CertHashString = certificate.GetCertHashString();
            Pkcs7 = Convert.ToBase64String(certificate.Export(X509ContentType.Cert));
        }

        [JsonConstructor]
        public SerializableCertificate(string Thumbprint, string Subject, string PublicKey, DateTime NotAfter, DateTime NotBefore, string Issuer, string SerialNumber, string CertHashString, string Pkcs7)
        {
            this.Thumbprint = Thumbprint;
            this.Subject = Subject;
            this.PublicKey = PublicKey;
            this.NotAfter = NotAfter;
            this.NotBefore = NotBefore;
            this.Issuer = Issuer;
            this.SerialNumber = SerialNumber;
            this.CertHashString = CertHashString;
            this.Pkcs7 = Pkcs7;
        }

        [ProtoMember(1)]
        public string CertHashString { get; set; }
        [ProtoMember(2)]
        public string Issuer { get; set; }
        [ProtoMember(3)]
        public DateTime NotAfter { get; set; }
        [ProtoMember(4)]
        public DateTime NotBefore { get; set; }
        [ProtoMember(5)]
        public string Pkcs7 { get; set; }
        [ProtoMember(6)]
        public string PublicKey { get; set; }
        [ProtoMember(7)]
        public string SerialNumber { get; set; }
        [ProtoMember(8)]
        public string Subject { get; set; }
        [ProtoMember(9)]
        public string Thumbprint { get; set; }
    }
}