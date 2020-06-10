// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
namespace AttackSurfaceAnalyzer.Objects
{
    public class Settings
    {
        #region Public Properties

        /// <summary>
        /// Schema Version of the database
        /// </summary>
        public int SchemaVersion { get; set; }

        /// <summary>
        /// How many database files to use/shard data across.
        /// </summary>
        public int ShardingFactor { get; set; }

        /// <summary>
        /// Should telemetry be sent.
        /// </summary>
        public bool TelemetryEnabled { get; set; }

        #endregion Public Properties
    }
}