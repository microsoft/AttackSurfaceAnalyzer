// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;

namespace AttackSurfaceAnalyzer.Objects
{
    public class OpenPortObject : CollectObject
    {
        public string? Address { get; set; }
        public string? Family { get; set; }
        public string? Type { get; set; }
        public int Port { get; set; }
        public string? ProcessName { get; set; }

        public OpenPortObject(int Port)
        {
            ResultType = RESULT_TYPE.PORT;
            this.Port = Port;
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