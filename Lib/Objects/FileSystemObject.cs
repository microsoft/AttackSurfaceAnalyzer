// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Text;
using AttackSurfaceAnalyzer.Utils;
using Newtonsoft.Json;
using Serilog;
using AttackSurfaceAnalyzer.Libs;


namespace AttackSurfaceAnalyzer.ObjectTypes
{
    public class FileSystemObject
    {

        public string Path;
        public string Permissions;
        public ulong Size;
        public string ContentHash;
        public List<DLLCHARACTERISTICS> Characteristics;
        public string SignatureStatus;

        public string RowKey
        {
            get
            {
                return CryptoHelpers.CreateHash(this.ToString());
            }
        }

        

        public override string ToString()
        {
            return string.Format("Path={0}, Permission={1}, Size={2}, ContentHash={3}", Path, Permissions, Size, ContentHash);
        }
    }
}