// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using ProtoBuf;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    /// <summary>
    ///     Abstract parent class that all Collected data inherits from.
    /// </summary>
    [ProtoContract]
    public abstract class MonitorObject : CollectObject
    {
        [ProtoMember(1)]
        public CHANGE_TYPE ChangeType { get; set; }
    }
}