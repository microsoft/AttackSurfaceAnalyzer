// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;
using System.Collections.Generic;

namespace AttackSurfaceAnalyzer.Objects
{
    public class GroupAccountObject : CollectObject
    {
        public string Caption { get; set; }
        public string Description { get; set; }
        public string Domain { get; set; }
        public string InstallDate { get; set; }
        public bool LocalAccount { get; set; }
        public string Name { get; set; }
        public string Status { get; set; }
        public string SID { get; set; }
        public int SIDType { get; set; }

        public List<string> Users { get; set; }

        public Dictionary<string, string> Properties { get; set; }

        public GroupAccountObject()
        {
            ResultType = RESULT_TYPE.GROUP;
            Users = new List<string>();
            Properties = new Dictionary<string, string>();
        }

        public override string Identity
        {
            get
            {
                return (Domain == null) ? Name : $"{Domain}\\{Name}";
            }
        }
    }
}