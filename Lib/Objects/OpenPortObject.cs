// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;

namespace AttackSurfaceAnalyzer.Objects
{
    public class OpenPortObject : CollectObject
    {
        public string address;
        public string family;
        public string type;
        public string port;
        public string processName;

        public OpenPortObject()
        {
            ResultType = RESULT_TYPE.PORT;
        }

        public override string Identity
        {
            get
            {
                return family + ":" + type + ":" + port;
            }
        }
    }
}