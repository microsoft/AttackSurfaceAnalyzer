// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;

namespace AttackSurfaceAnalyzer.Collectors
{
    public abstract class BaseMonitor : IPlatformRunnable
    {
#nullable disable

        #region Public Properties

        public string RunId { get; set; }
#nullable restore

        public RUN_STATUS RunStatus { get; set; }

        #endregion Public Properties

        #region Public Methods

        public abstract bool CanRunOnPlatform();

        public abstract void StartRun();

        public abstract void StopRun();

        #endregion Public Methods
    }
}