// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using AttackSurfaceAnalyzer.Types;

namespace AttackSurfaceAnalyzer.Objects
{

    public class UserAccountObject : CollectObject
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
        public string Name;

        public List<string> Groups;

        // Is the user Windows Administrator/sudoer

        public Dictionary<string, string> Properties;

        public UserAccountObject()
        {
            ResultType = RESULT_TYPE.USER;
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