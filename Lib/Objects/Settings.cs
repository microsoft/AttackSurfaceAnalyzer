// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
namespace AttackSurfaceAnalyzer.Objects
{
    public class Settings
    {
        public int Id { get; set; } = 0;
        public int ShardingFactor { get; set; }
        public bool TelemetryEnabled { get; set; }
        public int SchemaVersion { get; set; }

    }
}