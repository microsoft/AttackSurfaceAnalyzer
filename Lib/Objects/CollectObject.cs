// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.

using System.Globalization;
using MessagePack;
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    /// <summary>
    ///     Abstract parent class that all Collected data inherits from.
    /// </summary>
    [Union(0, typeof(CertificateObject))]
    [Union(1, typeof(ComObject))]
    [Union(2, typeof(CryptographicKeyObject))]
    [Union(3, typeof(DriverObject))]
    [Union(4, typeof(EventLogObject))]
    [Union(5, typeof(FileMonitorObject))]
    [Union(6, typeof(FileSystemObject))]
    [Union(7, typeof(FirewallObject))]
    [Union(8, typeof(OpenPortObject))]
    [Union(9, typeof(ProcessModuleObject))]
    [Union(10, typeof(ProcessObject))]
    [Union(11, typeof(RegistryObject))]
    [Union(12, typeof(ServiceObject))]
    [Union(13, typeof(TpmObject))]
    [Union(14, typeof(UserAccountObject))]
    [Union(15, typeof(GroupAccountObject))]
    [Union(16, typeof(WifiObject))]
    public abstract class CollectObject
    {
        [IgnoreMember]
        public abstract string Identity { get; }
        [IgnoreMember]
        public abstract RESULT_TYPE ResultType { get; }

        [SkipCompare]
        [IgnoreMember]
        public string RowKey => CryptoHelpers.CreateHash(Serialized);

        [SkipCompare]
        [IgnoreMember]
        public byte[] Serialized
        {
            get { return _serialized ??= SerializationUtils.Dehydrate(this); }
        }

        private byte[]? _serialized;
    }
}