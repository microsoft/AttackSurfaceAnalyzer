// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using System;
using System.Collections.Generic;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    public class FileSystemObject : CollectObject
    {
        public FileSystemObject(string Path)
        {
            this.Path = Path;
            ResultType = RESULT_TYPE.FILE;
        }

        public FileSystemObject()
        {
            Path = string.Empty;
            ResultType = RESULT_TYPE.FILE;
        }

        /// <summary>
        ///     If this is windows executable what DLL Characteristics are set
        /// </summary>
        public List<DLLCHARACTERISTICS>? Characteristics { get; set; }

        /// <summary>
        ///     A hash of the file (if collected)
        /// </summary>
        public string? ContentHash { get; set; }

        /// <summary>
        ///     When was the file created in UTC
        /// </summary>
        public DateTime Created { get; set; }

        /// <summary>
        ///     .ToString of Mono FileTypes result. Not available on Windows.
        /// </summary>
        public string? FileType { get; set; }

        /// <summary>
        ///     The group of the file.
        /// </summary>
        public string? Group { get; set; }

        /// <summary>
        ///     The File's path
        /// </summary>
        public override string Identity
        {
            get
            {
                return Path;
            }
        }

        /// <summary>
        ///     If the file is a directory
        /// </summary>
        public bool? IsDirectory { get; set; }

        /// <summary>
        ///     If the file is an executable
        /// </summary>
        public bool? IsExecutable { get; set; }

        /// <summary>
        ///     If the file is a link
        /// </summary>
        public bool? IsLink { get; set; }

        /// <summary>
        ///     When was the file last modified in UTC
        /// </summary>
        public DateTime LastModified { get; set; }

        /// <summary>
        ///     Signature information for signed Mac binaries.
        /// </summary>
        public MacSignature? MacSignatureStatus { get; set; }

        /// <summary>
        ///     The owner of the file.
        /// </summary>
        public string? Owner { get; set; }

        /// <summary>
        ///     The location on disk of the file
        /// </summary>
        public string Path { get; set; }

        /// <summary>
        ///     What are the permissions of this file.
        /// </summary>
        public Dictionary<string, string>? Permissions { get; set; }

        /// <summary>
        ///     A string representation of the permissions
        /// </summary>
        public string? PermissionsString { get; set; }

        /// <summary>
        ///     If the SetGid bit is set
        /// </summary>
        public bool? SetGid { get; set; }

        /// <summary>
        ///     If the SetUid bit is set
        /// </summary>
        public bool? SetUid { get; set; }

        /// <summary>
        ///     Signature information for signed Windows binaries.
        /// </summary>
        public Signature? SignatureStatus { get; set; }

        /// <summary>
        ///     File size in bytes
        /// </summary>
        public long? Size { get; set; }

        public long? SizeOnDisk { get; internal set; }

        /// <summary>
        ///     If this is a link where does it point to.
        /// </summary>
        public string? Target { get; set; }

        public bool ShouldSerializeCharacteristics()
        {
            return Characteristics?.Count > 0;
        }

        public bool ShouldSerializePermissions()
        {
            return Permissions?.Count > 0;
        }
    }
}