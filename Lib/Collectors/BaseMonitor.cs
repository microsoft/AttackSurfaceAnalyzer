// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;


namespace AttackSurfaceAnalyzer.Collectors
{
    public abstract class BaseMonitor : IPlatformRunnable
    {
#nullable disable
        public string RunId { get; set; }
#nullable restore

        public RUN_STATUS RunStatus { get; set; }

        public abstract void StartRun();

        public abstract void StopRun();

        public abstract bool CanRunOnPlatform();
    }
}