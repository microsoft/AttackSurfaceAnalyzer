// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;
using System.Collections.Generic;

namespace AttackSurfaceAnalyzer.Objects
{
    public class FileSystemObject : CollectObject
    {
        public override string Identity
        {
            get
            {
                return Path;
            }
        }
        public string Path { get; set; }
        public ulong Size { get; set; }
        public Signature SignatureStatus { get; set; }
        public string ContentHash { get; set; }
        public bool IsExecutable { get; set; }
        public bool IsDirectory { get; set; }
        public bool IsLink { get; set; }
        public string FileType { get; set; }
        public string Owner { get; set; }
        public string Group { get; set; }
        public bool SetGid { get; set; }
        public bool SetUid { get; set; }
        public string PermissionsString { get; set; }
        public List<string> Characteristics { get; set; }

        // If this is a link, where does it point to
        public string Target { get; set; }

        public Dictionary<string, string> Permissions { get; set; }

        public bool ShouldSerializeCharacteristics()
        {
            return Characteristics.Count > 0;
        }

        public bool ShouldSerializePermissions()
        {
            return Permissions.Count > 0;
        }

        public FileSystemObject()
        {
            ResultType = RESULT_TYPE.FILE;
            Characteristics = new List<string>();
            Permissions = new Dictionary<string, string>();
        }
    }
}