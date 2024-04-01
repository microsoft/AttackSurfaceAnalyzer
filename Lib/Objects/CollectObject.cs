// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Newtonsoft.Json;
using ProtoBuf;
using System.Globalization;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    /// <summary>
    ///     Abstract parent class that all Collected data inherits from.
    /// </summary>
    [ProtoContract]
    [ProtoInclude(1, typeof(CertificateObject))]
    [ProtoInclude(2, typeof(ComObject))]
    [ProtoInclude(3, typeof(CryptographicKeyObject))]
    [ProtoInclude(4, typeof(DriverObject))]
    [ProtoInclude(5, typeof(EventLogObject))]
    [ProtoInclude(6, typeof(FileMonitorObject))]
    [ProtoInclude(7, typeof(FileSystemObject))]
    [ProtoInclude(8, typeof(FirewallObject))]
    [ProtoInclude(9, typeof(OpenPortObject))]
    [ProtoInclude(10, typeof(ProcessObject))]
    [ProtoInclude(11, typeof(RegistryObject))]
    [ProtoInclude(12, typeof(ServiceObject))]
    [ProtoInclude(13, typeof(TpmObject))]
    [ProtoInclude(14, typeof(UserAccountObject))]
    [ProtoInclude(15, typeof(GroupAccountObject))]
    [ProtoInclude(16, typeof(WifiObject))]
    public abstract class CollectObject
    {
        public abstract string Identity { get; }
        public abstract RESULT_TYPE ResultType { get; }

        [SkipCompare]
        [JsonIgnore]
        public string RowKey
        {
            get
            {
                return Serialized.GetHashCode().ToString(CultureInfo.InvariantCulture);
            }
        }
        
        [SkipCompare]
        [JsonIgnore]
        public byte[] Serialized
        {
            get
            {
                if (_serialized == null)
                {
                    _serialized = JsonUtils.Dehydrate(this);
                }

                return _serialized;
            }
        }

        private byte[]? _serialized = null;
    }
}