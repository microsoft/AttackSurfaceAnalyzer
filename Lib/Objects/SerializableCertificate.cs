// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using System;
using System.Security.Cryptography.X509Certificates;
using MessagePack;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [MessagePackObject]
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

        [SerializationConstructor]
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

        [Key(7)]
        public string CertHashString { get; set; }
        [Key(5)]
        public string Issuer { get; set; }
        [Key(3)]
        public DateTime NotAfter { get; set; }
        [Key(4)]
        public DateTime NotBefore { get; set; }
        [Key(8)]
        public string Pkcs7 { get; set; }
        [Key(2)]
        public string PublicKey { get; set; }
        [Key(6)]
        public string SerialNumber { get; set; }
        [Key(1)]
        public string Subject { get; set; }
        [Key(0)]
        public string Thumbprint { get; set; }
    }
}