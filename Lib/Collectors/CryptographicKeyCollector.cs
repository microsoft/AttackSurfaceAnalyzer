// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using System;
using System.Runtime.InteropServices;
using System.Threading;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Collectors
{
    public class CryptographicKeyCollector : BaseCollector
    {
        public CryptographicKeyCollector(CollectorOptions? opts = null, Action<CollectObject>? changeHandler = null) : base(opts, changeHandler)
        {
        }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        }

        internal override void ExecuteInternal(CancellationToken cancellationToken)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                // Foreach (var ksp in ksps){ enumeratekeys(ksp) }
            }
        }
    }
}