// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System.Runtime.ConstrainedExecution;
using AttackSurfaceAnalyzer.Types;

namespace AttackSurfaceAnalyzer.Objects
{
    public class CertificateObject : CollectObject
    {
        public string StoreLocation { get; set; }
        public string StoreName { get; set; }
        public string CertificateHashString { get { return Certificate.CertHashString; } }
        public string Subject { get { return Certificate.Subject; } }
        public string? Pkcs7 { get; set; }
        public SerializableCertificate Certificate { get; set; }

        public CertificateObject(string StoreLocation, string StoreName, SerializableCertificate Certificate, string? Pkcs7 = null)
        {
            this.StoreLocation = StoreLocation;
            this.StoreName = StoreName;
            this.Certificate = Certificate;
            ResultType = RESULT_TYPE.CERTIFICATE;
            this.Pkcs7 = Pkcs7;
        }

        public override string Identity
        {
            get
            {
                return $"{StoreLocation}{StoreName}{CertificateHashString}";
            }
        }
    }
}
