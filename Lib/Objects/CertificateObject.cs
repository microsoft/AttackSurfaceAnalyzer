// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.Text;
using Serilog;

namespace AttackSurfaceAnalyzer.ObjectTypes
{
    public class CertificateObject
    {
        public string StoreLocation;
        public string StoreName;
        public string CertificateHashString;
        public string Subject;
    }
}
