// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.

using MessagePack;
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Newtonsoft.Json;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [MessagePackObject]
    public class OpenPortObject : CollectObject
    {
        public OpenPortObject(int Port, TRANSPORT Type, ADDRESS_FAMILY AddressFamily = ADDRESS_FAMILY.Unspecified)
        {
            this.Port = Port;
            this.Type = Type;
            this.AddressFamily = AddressFamily;
        }

        [IgnoreMember]
        public override RESULT_TYPE ResultType => RESULT_TYPE.PORT;

        [Key(3)]
        public string? Address { get; set; }

        /// <summary>
        ///     InterNetwork is IPv4 InterNetworkV6 is IPv6
        /// </summary>
        [Key(2)]
        public ADDRESS_FAMILY AddressFamily { get; set; }

        /// <summary>
        ///     $"{Address}:{Family}:{Type}:{Port}:{ProcessName}"
        /// </summary>
        [IgnoreMember]
        public override string Identity => $"{Address}:{AddressFamily}:{Type}:{Port}:{ProcessName}";

        /// <summary>
        ///     The port number
        /// </summary>
        [Key(0)]
        public int Port { get; set; }

        /// <summary>
        /// The associated process if known
        /// </summary>
        [Key(4)]
        public string? ProcessName { get; set; }

        /// <summary>
        /// The associated process ID if known
        /// </summary>
        [Key(5)]
        public int? ProcessId { get; set; }

        /// <summary>
        ///     TCP or UDP
        /// </summary>
        [Key(1)]
        public TRANSPORT Type { get; set; }
    }
}