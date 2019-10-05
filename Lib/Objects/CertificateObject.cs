// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;
using System;

namespace AttackSurfaceAnalyzer.Objects
{
    public class CertificateObject : CollectObject
    {
        public string StoreLocation { get; set; }
        public string StoreName { get; set; }
        public string CertificateHashString { get; set; }
        public string Subject { get; set; }
        public string Pkcs12 { get; set; }
        public string Pkcs7 { get; set; }

        public CertificateObject()
        {
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
