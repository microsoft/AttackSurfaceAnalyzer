// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using ProtoBuf;
using System.IO;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [ProtoContract]
    public class FileMonitorObject : MonitorObject
    {
        public FileMonitorObject(string PathIn)
        {
            Path = PathIn;
        }
        public override RESULT_TYPE ResultType => RESULT_TYPE.FILEMONITOR;

        [ProtoMember(9)]
        public string? ExtendedResults { get; set; }
        [ProtoMember(2)]
        public FileSystemObject? FileSystemObject { get; set; }

        public override string Identity
        {
            get
            {
                return Path;
            }
        }

        [ProtoMember(3)]
        public string? Name { get; set; }
        [ProtoMember(4)]
        public NotifyFilters? NotifyFilters { get; set; }
        [ProtoMember(5)]
        public string? OldName { get; set; }
        [ProtoMember(6)]
        public string? OldPath { get; set; }
        [ProtoMember(7)]
        public string Path { get; set; }
        [ProtoMember(8)]
        public string? Timestamp { get; set; }
    }
}