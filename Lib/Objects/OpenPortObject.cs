// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Text;
using AttackSurfaceAnalyzer.Utils;
using Newtonsoft.Json;
using Serilog;

namespace AttackSurfaceAnalyzer.Objects
{
    public class OpenPortObject : CollectObject
    {
        public string address;
        public string family;
        public string type;
        public string port;
        public string processName;
    }
}