using PeNet.Authenticode;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace AttackSurfaceAnalyzer.Objects
{
    public class Signature
    {
        public Signature(AuthenticodeInfo authenticodeInfo)
        {
            if (authenticodeInfo != null)
            {
                IsAuthenticodeValid = authenticodeInfo.IsAuthenticodeValid;
                SignedHash = authenticodeInfo.SignedHash;
                SignerSerialNumber = authenticodeInfo.SignerSerialNumber;
                SigningCertificate = new SerializableCertificate(authenticodeInfo.SigningCertificate);
            }
        }

        public Signature() 
        { 
        }

        public bool IsAuthenticodeValid { get; set; }
        public byte[] SignedHash { get; set; }
        public string SignerSerialNumber { get; set; }
        public SerializableCertificate SigningCertificate { get; set; }

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
    }
}
