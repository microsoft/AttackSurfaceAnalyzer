// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Newtonsoft.Json;
using ProtoBuf;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [ProtoContract(SkipConstructor = true)]
    public class OpenPortObject : CollectObject
    {
        [JsonConstructor]
        public OpenPortObject(int Port, TRANSPORT Type) : this(Port, Type, ADDRESS_FAMILY.Unspecified) { }

        public OpenPortObject(int Port, TRANSPORT Type, ADDRESS_FAMILY AddressFamily)
        {
            this.Port = Port;
            this.Type = Type;
            this.AddressFamily = AddressFamily;
        }

        public override RESULT_TYPE ResultType => RESULT_TYPE.PORT;
        [ProtoMember(1)]
        public string? Address { get; set; }

        /// <summary>
        ///     InterNetwork is IPv4 InterNetworkV6 is IPv6
        /// </summary>
        [ProtoMember(2)]
        public ADDRESS_FAMILY AddressFamily { get; set; }

        /// <summary>
        ///     $"{Address}:{Family}:{Type}:{Port}:{ProcessName}"
        /// </summary>
        public override string Identity
        {
            get
            {
                return $"{Address}:{AddressFamily}:{Type}:{Port}:{ProcessName}";
            }
        }

        /// <summary>
        ///     The port number
        /// </summary>
        [ProtoMember(3)]
        public int Port { get; set; }

        /// <summary>
        /// The associated process if known
        /// </summary>
        [ProtoMember(4)]
        public string? ProcessName { get; set; }

        /// <summary>
        /// The associated process ID if known
        /// </summary>
        [ProtoMember(5)]
        public int? ProcessId { get; set; }

        /// <summary>
        ///     TCP or UDP
        /// </summary>
        [ProtoMember(6)]
        public TRANSPORT Type { get; set; }
    }
}