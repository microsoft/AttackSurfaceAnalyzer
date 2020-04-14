using Newtonsoft.Json;
using System;
using System.Security.Cryptography.X509Certificates;

namespace AttackSurfaceAnalyzer.Objects
{
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
        }

        [JsonConstructor]
        public SerializableCertificate(string Thumbprint, string Subject, string PublicKey, DateTime NotAfter, DateTime NotBefore, string Issuer, string SerialNumber, string CertHashString)
        {
            this.Thumbprint = Thumbprint;
            this.Subject = Subject;
            this.PublicKey = PublicKey;
            this.NotAfter = NotAfter;
            this.NotBefore = NotBefore;
            this.Issuer = Issuer;
            this.SerialNumber = SerialNumber;
            this.CertHashString = CertHashString;
        }

        public string Thumbprint { get; set; }
        public string Subject { get; set; }
        public string PublicKey { get; set; }
        public DateTime NotAfter { get; set; }
        public DateTime NotBefore { get; set; }
        public string Issuer { get; set; }
        public string SerialNumber { get; set; }
        public string CertHashString { get; set; }
    }
}