// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using System;
using System.Runtime.InteropServices;
using System.Threading;

namespace AttackSurfaceAnalyzer.Collectors
{
    public class CryptographicKeyCollector : BaseCollector
    {
        #region Public Constructors

        public CryptographicKeyCollector(CollectCommandOptions? opts = null, Action<CollectObject>? changeHandler = null) : base(opts, changeHandler)
        {
        }

        #endregion Public Constructors

        #region Public Methods

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        }

        #endregion Public Methods

        #region Internal Methods

        internal override void ExecuteInternal(CancellationToken cancellationToken)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                // Foreach (var ksp in ksps){ enumeratekeys(ksp) }
            }
        }

        #endregion Internal Methods
    }
}