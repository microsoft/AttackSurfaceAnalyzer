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
        public string pkcs12;

        public override string Identity
        {
            get
            {
                return (StoreName + StoreLocation + CertificateHashString);
            }
        }

        public override RESULT_TYPE ResultType
        {
            get
            {
                return RESULT_TYPE.CERTIFICATE;
            }
        }
    }
}
