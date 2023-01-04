// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.

using MessagePack;
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Newtonsoft.Json;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [MessagePackObject]
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

        public string? Address { get; set; }

        /// <summary>
        ///     InterNetwork is IPv4 InterNetworkV6 is IPv6
        /// </summary>
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
        public int Port { get; set; }

        /// <summary>
        /// The associated process if known
        /// </summary>
        public string? ProcessName { get; set; }

        /// <summary>
        /// The associated process ID if known
        /// </summary>
        public int? ProcessId { get; set; }

        /// <summary>
        ///     TCP or UDP
        /// </summary>
        public TRANSPORT Type { get; set; }
    }
}