// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using AttackSurfaceAnalyzer.Utils;
using Newtonsoft.Json;
using Serilog;

namespace AttackSurfaceAnalyzer.Objects
{
    public class UserGroupObject : CollectObject
    {
        public string AccountType;
        public string Caption;
        public string Description;
        public string Disabled;
        public string Domain;
        public string FullName;
        public string InstallDate;
        public string LocalAccount;
        public string Lockout;
        public string Name;
        public string PasswordChangeable;
        public string PasswordExpires;
        public string PasswordRequired;
        public string SID;
        public string UID;
        public string GID;
        public string Inactive;
        public string HomeDirectory;
        public string Shell;
        public string PasswordStorageAlgorithm;
        public bool Privileged;

        public List<string> Users;

        // Is the user Windows Administrator/sudoer

        public Dictionary<string, string> Properties;

        public UserGroupObject()
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