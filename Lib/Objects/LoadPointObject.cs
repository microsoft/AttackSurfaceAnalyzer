// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Microsoft.Win32;
using System.Collections.Generic;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    /// <summary>
    ///     A place where the operating system is told to load code, joined at collection time to the binary
    ///     it resolves to.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         Analysis rules are evaluated against the before and after states of a single object and cannot
    ///         reach a second one, so a rule over a <see cref="RegistryObject" /> can never ask about the
    ///         file that key points at. This object performs that join during collection: it carries the
    ///         source key and its ACL, the resolved target path, the target's ACL, and flat summary flags a
    ///         rule can test directly.
    ///     </para>
    ///     <para>
    ///         Summary fields are deliberately booleans and strings. Dotted field navigation in rules is
    ///         shallow and regex cannot match dictionary-typed fields, so nested structures are not
    ///         interrogable.
    ///     </para>
    /// </remarks>
    public class LoadPointObject : CollectObject
    {
        public LoadPointObject(string LoadPointType, RegistryObject SourceKey)
        {
            this.LoadPointType = LoadPointType;
            this.SourceKey = SourceKey;
        }

        public override RESULT_TYPE ResultType => RESULT_TYPE.LOADPOINT;

        /// <summary>
        ///     A load point is identified by the key and value it came from together with what that resolved
        ///     to, so that two plugins registered under one key remain distinct objects.
        /// </summary>
        public override string Identity => $"{LoadPointType}_{SourceKey.Identity}_{SourceValueName}_{TargetClsid}_{TargetPath}";

        /// <summary>
        ///     Which kind of load point this is, e.g. ComServer, StaticPluginMap, AppInit_DLLs, Service.
        /// </summary>
        public string LoadPointType { get; set; }

        /// <summary>
        ///     The registry key that names the code to load, including its ACL.
        /// </summary>
        public RegistryObject SourceKey { get; set; }

        /// <summary>
        ///     The value under <see cref="SourceKey" /> this load point came from. Empty for a key's default
        ///     value.
        /// </summary>
        public string? SourceValueName { get; set; }

        /// <summary>
        ///     The raw value data before expansion, retained so a rule can see what was actually written.
        /// </summary>
        public string? SourceValueData { get; set; }

        /// <summary>
        ///     True when <see cref="SourceKey" /> can be modified by an unprivileged user, meaning an
        ///     attacker can repoint this load point at code of their choosing.
        /// </summary>
        public bool SourceKeyUserWritable { get; set; }

        /// <summary>
        ///     The steps taken to get from the source key to the target binary, for triage.
        /// </summary>
        public List<string> ResolutionChain { get; set; } = new List<string>();

        /// <summary>
        ///     The CLSID this load point resolved through, if it referenced one.
        /// </summary>
        public string? TargetClsid { get; set; }

        /// <summary>
        ///     The resolved path of the binary that will be loaded.
        /// </summary>
        public string? TargetPath { get; set; }

        /// <summary>
        ///     The target binary, including its ACL. Null when the target does not exist.
        /// </summary>
        public FileSystemObject? Target { get; set; }

        /// <summary>
        ///     Whether the target binary is present on disk. A missing target at a path an unprivileged user
        ///     can write is the exploitable case, so this is asserted directly rather than inferred from a
        ///     null Target, which is also what a failed collection produces.
        /// </summary>
        public bool TargetExists { get; set; }

        /// <summary>
        ///     True when the target's ACL could not be read at all, so <see cref="TargetUserWritable" /> is
        ///     not a statement about the target's security.
        /// </summary>
        public bool TargetAclUnavailable { get; set; }

        /// <summary>
        ///     Whether <see cref="TargetUserWritable" /> describes the target itself or the directory that
        ///     would receive it: Target, NearestExistingParent, or None.
        /// </summary>
        public string TargetAclSource { get; set; } = "None";

        /// <summary>
        ///     True when the target names a location on another machine, either a UNC path or a path through
        ///     a mapped network drive. The target is reported but is not resolved unless collection was asked
        ///     to follow network paths, because reaching it connects to a host named by whoever could write
        ///     the source key and authenticates as the account running the collection.
        /// </summary>
        public bool TargetIsNetworkPath { get; set; }

        /// <summary>
        ///     True when an unprivileged user can write the target binary, or when the target is missing and
        ///     an unprivileged user can create it in the nearest existing parent directory.
        /// </summary>
        public bool TargetUserWritable { get; set; }

        /// <summary>
        ///     The closest ancestor directory of <see cref="TargetPath" /> that exists on disk. Populated
        ///     when the target is missing, because that directory's ACL is what decides whether an attacker
        ///     can supply the file.
        /// </summary>
        public string? NearestExistingParentPath { get; set; }

        /// <summary>
        ///     The nearest existing parent directory, including its ACL.
        /// </summary>
        public FileSystemObject? NearestExistingParent { get; set; }

        /// <summary>
        ///     The registry view this load point was collected from.
        /// </summary>
        public RegistryView View { get; set; }
    }
}
