// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using ProtoBuf;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [ProtoContract(SkipConstructor = true)]
    public class ComObject : CollectObject
    {
        /// <summary>
        ///     This is the correct constructor to use to create a ComObject.
        /// </summary>
        /// <param name="Key"> The RegistryObject this ComObject is based on. </param>
        public ComObject(RegistryObject Key) : base()
        {
            this.Key = Key;
        }
        public override RESULT_TYPE ResultType => RESULT_TYPE.COM;

        /// <summary>
        ///     A COM Object's identity is the same as the Registry Key which specifies it
        /// </summary>
        public override string Identity
        {
            get
            {
                return Key.Identity;
            }
        }

        /// <summary>
        ///     The Registry Key which specifies this COM object
        /// </summary>
        [ProtoMember(1)]
        public RegistryObject Key { get; set; }

        /// <summary>
        ///     The associated binary found (if any) in the x64 view of the registry
        /// </summary>
        [ProtoMember(2)]
        public FileSystemObject? x64_Binary { get; set; }

        /// <summary>
        ///     The associated binary found (if any) in the x86 view of the registry
        /// </summary>
        [ProtoMember(3)]
        public FileSystemObject? x86_Binary { get; set; }
    }
}