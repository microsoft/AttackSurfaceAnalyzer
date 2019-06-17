﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System.Text;
using AttackSurfaceAnalyzer.Utils;
using Newtonsoft.Json;
using Serilog;

namespace AttackSurfaceAnalyzer.Objects
{
    public class ServiceObject : CollectObject
    {
        public string ServiceName { get; set; }
        public string StartType { get; set; }
        public string DisplayName { get; set; }
        public string CurrentState { get; set; }

        public override string Identity
        {
            get
            {
                return ServiceName;
            }
        }

        public override RESULT_TYPE ResultType
        {
            get
            {
                return RESULT_TYPE.SERVICES;
            }
        }
    }
}