// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;



namespace AttackSurfaceAnalyzer.Objects
{
    public class FileSystemObject : CollectObject
    {

        public string Path;
        public string Permissions;
        public ulong Size;
        public string ContentHash;
        public List<DLLCHARACTERISTICS> Characteristics;
        public string SignatureStatus;
        public bool IsExecutable;

        public override string Identity {
            get
            {
                return Path;
            }
        }

        public override RESULT_TYPE ResultType
        {
            get
            {
                return RESULT_TYPE.FILE;
            }
        }
    }
}