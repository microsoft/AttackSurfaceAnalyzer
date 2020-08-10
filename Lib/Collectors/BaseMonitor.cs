// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Collectors
{
    public abstract class BaseMonitor : IPlatformRunnable
    {
#nullable disable

        public string RunId { get; set; }
#nullable restore

        public RUN_STATUS RunStatus { get; set; }

        public abstract bool CanRunOnPlatform();

        public abstract void StartRun();

        public abstract void StopRun();
    }
}