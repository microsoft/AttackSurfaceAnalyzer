// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using AttackSurfaceAnalyzer.Types;

namespace AttackSurfaceAnalyzer.Objects
{
    public class GroupAccountObject : CollectObject
    {
        public string Caption;
        public string Description;
        public string InstallDate;
        public string Status;
        public bool LocalAccount;
        public string SID;
        public int SIDType;
        public string Domain;
        public string Name;

        public List<string> Users;

        public Dictionary<string, string> Properties;

        public GroupAccountObject()
        {
            ResultType = RESULT_TYPE.GROUP;
        }

        public override string Identity
        {
            get
            {
                return (Domain == null) ? Name : String.Format(@"{0}\{1}", Domain, Name);
            }
        }
    }
}