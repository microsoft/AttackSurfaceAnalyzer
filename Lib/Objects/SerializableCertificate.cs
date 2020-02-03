using System;
using System.Security.Cryptography.X509Certificates;

namespace AttackSurfaceAnalyzer.Objects
{
    public class SerializableCertificate
    {
        public SerializableCertificate (X509Certificate2 certificate)
        {
            Thumbprint = certificate.Thumbprint;
            Subject = certificate.Subject;
            PublicKey = certificate.PublicKey.EncodedKeyValue.Format(true);
            NotAfter = certificate.NotAfter;
            NotBefore = certificate.NotBefore;
            Issuer = certificate.Issuer;
            SerialNumber = certificate.SerialNumber;
        }

        public SerializableCertificate()
        {
        }

        public string Thumbprint { get; set; }
        public string Subject { get; set; }
        public string PublicKey { get; set; }
        public DateTime NotAfter { get; set; }
        public DateTime NotBefore { get; set; }
        public string Issuer { get; set; }
        public string SerialNumber { get; set; }
    }
}