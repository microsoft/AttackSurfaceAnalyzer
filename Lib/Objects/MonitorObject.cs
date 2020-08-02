// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;

namespace AttackSurfaceAnalyzer.Objects
{
    /// <summary>
    ///     Abstract parent class that all Collected data inherits from.
    /// </summary>
    public abstract class MonitorObject : CollectObject
    {
        public CHANGE_TYPE ChangeType { get; set; }
    }
}