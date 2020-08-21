// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using System;
using System.Collections.Generic;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    public class AsaRun
    {
        public AsaRun(string RunId, DateTime Timestamp, string Version, PLATFORM Platform, List<RESULT_TYPE> ResultTypes, RUN_TYPE Type)
        {
            this.RunId = RunId;
            this.Timestamp = Timestamp;
            this.Version = Version;
            this.Platform = Platform;
            this.ResultTypes = ResultTypes;
            this.Type = Type;
        }

        public PLATFORM Platform { get; set; }
        public List<RESULT_TYPE> ResultTypes { get; set; }
        public string RunId { get; set; }
        public DateTime Timestamp { get; set; }
        public RUN_TYPE Type { get; set; }
        public string Version { get; set; }
    }
}