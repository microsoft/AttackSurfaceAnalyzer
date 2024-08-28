// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using ProtoBuf;
using System;
using System.Collections.Generic;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [ProtoContract]
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
        public override RESULT_TYPE ResultType => RESULT_TYPE.FILE;
        /// <summary>
        ///     The File's path
        /// </summary>
        public override string Identity => Path;
        /// <summary>
        ///     If this is windows executable what DLL Characteristics are set
        /// </summary>
        [ProtoMember(3)]
        public List<DLLCHARACTERISTICS>? Characteristics { get; set; }

        /// <summary>
        ///     A hash of the file (if collected)
        /// </summary>
        [ProtoMember(1)]
        public string? ContentHash { get; set; }

        /// <summary>
        ///     When was the file created in UTC
        /// </summary>
        [ProtoMember(2)]
        public DateTime Created { get; set; }

        /// <summary>
        ///     .ToString of Mono FileTypes result. Not available on Windows.
        /// </summary>
        [ProtoMember(5)]
        public string? FileType { get; set; }

        /// <summary>
        ///     The group of the file.
        /// </summary>
        [ProtoMember(6)]
        public string? Group { get; set; }

        /// <summary>
        ///     If the file is a directory
        /// </summary>
        [ProtoMember(7)]
        public bool? IsDirectory { get; set; }

        /// <summary>
        ///     If the file is an executable
        /// </summary>
        [ProtoMember(8)]
        public bool? IsExecutable { get; set; }

        /// <summary>
        /// The type of the executable if it is one
        /// </summary>
        [ProtoMember(9)]
        public EXECUTABLE_TYPE ExecutableType { get; set; } = EXECUTABLE_TYPE.UNKNOWN;

        /// <summary>
        ///     If the file is a link
        /// </summary>
        [ProtoMember(10)]
        public bool? IsLink { get; set; }

        /// <summary>
        ///     When was the file last modified in UTC
        /// </summary>
        [ProtoMember(11)]
        public DateTime LastModified { get; set; }

        /// <summary>
        ///     Signature information for signed Mac binaries.
        /// </summary>
        [ProtoMember(12)]
        public MacSignature? MacSignatureStatus { get; set; }

        /// <summary>
        ///     The owner of the file.
        /// </summary>
        [ProtoMember(13)]
        public string? Owner { get; set; }

        /// <summary>
        ///     The location on disk of the file
        /// </summary>
        [ProtoMember(14)] 
        public string Path { get; set; }

        /// <summary>
        ///     What are the permissions of this file.
        /// </summary>
        [ProtoMember(15)] 
        public Dictionary<string, string>? Permissions { get; set; }

        /// <summary>
        ///     A string representation of the permissions
        /// </summary>
        [ProtoMember(16)] 
        public string? PermissionsString { get; set; }

        /// <summary>
        ///     If the SetGid bit is set
        /// </summary>
        [ProtoMember(17)] 
        public bool? SetGid { get; set; }

        /// <summary>
        ///     If the SetUid bit is set
        /// </summary>
        [ProtoMember(18)]
        public bool? SetUid { get; set; }

        /// <summary>
        ///     Signature information for signed Windows binaries.
        /// </summary>
        [ProtoMember(19)]
        public Signature? SignatureStatus { get; set; }

        /// <summary>
        ///     File size in bytes
        /// </summary>
        [ProtoMember(20)]
        public long? Size { get; set; }

        [ProtoMember(21)] 
        public long? SizeOnDisk { get; internal set; }

        /// <summary>
        ///     If this is a link where does it point to.
        /// </summary>
        [ProtoMember(4)] 
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