// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
namespace AttackSurfaceAnalyzer.Objects
{
    public class CertificateObject : CollectObject
    {
        public string StoreLocation;
        public string StoreName;
        public string CertificateHashString;
        public string Subject;
        public string Pkcs12;

        public CertificateObject()
        {
            ResultType = RESULT_TYPE.CERTIFICATE;
        }

        public override string Identity
        {
            get
            {
                return CertificateHashString;
            }
        }
    }
}
