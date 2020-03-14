// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;

namespace AttackSurfaceAnalyzer.Objects
{
    public class CertificateObject : CollectObject
    {
        public string StoreLocation { get; set; }
        public string StoreName { get; set; }
        public string CertificateHashString { get; set; }
        public string? Subject { get; set; }
        public string? Pkcs7 { get; set; }

        public CertificateObject(string StoreLocation, string StoreName, string CertificateHashString)
        {
            this.StoreLocation = StoreLocation;
            this.StoreName = StoreName;
            this.CertificateHashString = CertificateHashString;
            ResultType = RESULT_TYPE.CERTIFICATE;
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
