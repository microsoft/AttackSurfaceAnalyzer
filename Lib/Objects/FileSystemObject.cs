// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;
using System.Collections.Generic;

namespace AttackSurfaceAnalyzer.Objects
{
    public class FileSystemObject : CollectObject
    {
        public string Path { get; set; }
        public string PermissionsString { get; set; }
        public List<KeyValuePair<string,string>> Permissions { get; set; }
        public ulong Size { get; set; }
        public string ContentHash { get; set; }
        public List<string> Characteristics { get; set; }
        public string SignatureStatus { get; set; }
        public bool IsExecutable { get; set; }
        public bool IsDirectory { get; set; }

        public string Owner { get; set; }
        public string Group { get; set; }
        public bool SetGid { get; set; }
        public bool SetUid { get; set; }

        public FileSystemObject()
        {
            ResultType = RESULT_TYPE.FILE;
        }

        public override string Identity
        {
            get
            {
                return Path;
            }
        }
    }
}