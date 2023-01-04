// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using System;
using System.Collections.Generic;
using MessagePack;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [MessagePackObject]
    public class FileSystemObject : CollectObject
    {
        public FileSystemObject(string Path)
        {
            this.Path = Path;
        }

        public FileSystemObject()
        {
            Path = string.Empty;
        }

        [IgnoreMember]
        public override RESULT_TYPE ResultType => RESULT_TYPE.FILE;

        /// <summary>
        ///     If this is windows executable what DLL Characteristics are set
        /// </summary>
        [Key(12)]
        public List<DLLCHARACTERISTICS>? Characteristics { get; set; }

        /// <summary>
        ///     A hash of the file (if collected)
        /// </summary>
        [Key(1)]
        public string? ContentHash { get; set; }

        /// <summary>
        ///     When was the file created in UTC
        /// </summary>
        [Key(2)]
        public DateTime Created { get; set; }

        /// <summary>
        ///     .ToString of Mono FileTypes result. Not available on Windows.
        /// </summary>
        [Key(3)]
        public string? FileType { get; set; }

        /// <summary>
        ///     The group of the file.
        /// </summary>
        [Key(4)]
        public string? Group { get; set; }

        /// <summary>
        ///     The File's path
        /// </summary>
        [IgnoreMember]
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
        [Key(5)]
        public bool? IsDirectory { get; set; }

        /// <summary>
        ///     If the file is an executable
        /// </summary>
        [Key(6)]
        public bool? IsExecutable { get; set; }

        /// <summary>
        /// The type of the executable if it is one
        /// </summary>
        [Key(7)]
        public EXECUTABLE_TYPE ExecutableType { get; set; } = EXECUTABLE_TYPE.UNKNOWN;

        /// <summary>
        ///     If the file is a link
        /// </summary>
        [Key(8)]
        public bool? IsLink { get; set; }

        /// <summary>
        ///     When was the file last modified in UTC
        /// </summary>
        [Key(9)]
        public DateTime LastModified { get; set; }

        /// <summary>
        ///     Signature information for signed Mac binaries.
        /// </summary>
        [Key(10)]
        public MacSignature? MacSignatureStatus { get; set; }

        /// <summary>
        ///     The owner of the file.
        /// </summary>
        [Key(11)]
        public string? Owner { get; set; }

        /// <summary>
        ///     The location on disk of the file
        /// </summary>
        [Key(0)]
        public string Path { get; set; }

        /// <summary>
        ///     What are the permissions of this file.
        /// </summary>
        [Key(13)]
        public Dictionary<string, string>? Permissions { get; set; }

        /// <summary>
        ///     A string representation of the permissions
        /// </summary>
        [Key(14)]
        public string? PermissionsString { get; set; }

        /// <summary>
        ///     If the SetGid bit is set
        /// </summary>
        [Key(15)]
        public bool? SetGid { get; set; }

        /// <summary>
        ///     If the SetUid bit is set
        /// </summary>
        [Key(16)]
        public bool? SetUid { get; set; }

        /// <summary>
        ///     Signature information for signed Windows binaries.
        /// </summary>
        [Key(17)]
        public Signature? SignatureStatus { get; set; }

        /// <summary>
        ///     File size in bytes
        /// </summary>
        [Key(18)]
        public long? Size { get; set; }

        [Key(19)]
        public long? SizeOnDisk { get; internal set; }

        /// <summary>
        ///     If this is a link where does it point to.
        /// </summary>
        [Key(20)]
        public string? Target { get; set; }
    }
}