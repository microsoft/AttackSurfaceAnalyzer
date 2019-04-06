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
        public static List<string> SIGNED_EXTENSIONS = new List<string> { "dll", "exe", "cab", "ocx" };

        public string Path;
        public string Permissions;
        public ulong Size;
        public string ContentHash;

        public string SignatureStatus
        {
            get
            {
                if (!NeedsSignature())
                {
                    return "No signature required";
                }
                string sigStatus = AuthenticodeTools.WinVerifyTrust(Path);

                return sigStatus;
            }
        }

        public string RowKey
        {
            get
            {
                return CryptoHelpers.CreateHash(this.ToString());
            }
        }

        public bool NeedsSignature()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var _p = Path.ToLower().Trim();
                foreach (var ext in SIGNED_EXTENSIONS)
                {
                    if (_p.EndsWith("." + ext))
                    {
                        return true;
                    }
                }
                return false;
            }
            else
            {
                return false;
            }
        }

        public override string ToString()
        {
            return string.Format("Path={0}, Permission={1}, Size={2}, ContentHash={3}", Path, Permissions, Size, ContentHash);
        }

        public string ToJson()
        {
            var _path = JsonConvert.ToString(Path);
            var _permission = JsonConvert.ToString(Permissions);
            var _size = JsonConvert.ToString(Size);
            var _contentHash = JsonConvert.ToString(ContentHash);

            var sb = new StringBuilder();
            sb.Append("{");
            sb.AppendFormat("\"path\":{0},", _path);
            sb.AppendFormat("\"permission\":{0},", _permission);
            sb.AppendFormat("\"size\":{0},", _size);
            sb.AppendFormat("\"content_hash\":{0}", _contentHash);
            sb.AppendLine("}");
            return sb.ToString();
        }
    }
}