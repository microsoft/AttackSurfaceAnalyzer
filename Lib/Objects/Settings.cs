// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
namespace AttackSurfaceAnalyzer.Objects
{
    public class Settings
    {
        /// <summary>
        /// How many database files to use/shard data across.
        /// </summary>
        public int ShardingFactor { get; set; }
        /// <summary>
        /// Should telemetry be sent.
        /// </summary>
        public bool TelemetryEnabled { get; set; }
        /// <summary>
        /// Schema Version of the database
        /// </summary>
        public int SchemaVersion { get; set; }
    }
}