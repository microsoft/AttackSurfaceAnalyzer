// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System.Net.Sockets;
using AttackSurfaceAnalyzer.Types;

namespace AttackSurfaceAnalyzer.Objects
{
    public class OpenPortObject : CollectObject
    {
        public string? Address { get; set; }
        public AddressFamily Family { get; set; }
        public TRANSPORT Type { get; set; }
        public int Port { get; set; }
        public string? ProcessName { get; set; }

        public OpenPortObject(int Port, TRANSPORT Type)
        {
            ResultType = RESULT_TYPE.PORT;
            this.Port = Port;
            this.Type = Type;
        }

        public override string Identity
        {
            get
            {
                return $"{Address}:{Family}:{Type}:{Port}:{ProcessName}";
            }
        }
    }
}