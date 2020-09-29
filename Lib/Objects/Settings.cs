// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    public class Settings
    {
        /// <summary>
        ///     Schema Version of the database
        /// </summary>
        public int SchemaVersion { get; set; }

        /// <summary>
        ///     How many database files to use/shard data across.
        /// </summary>
        public int ShardingFactor { get; set; }
    }
}