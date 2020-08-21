// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    ///     Collects metadata about processes on the local computer.
    /// </summary>
    public class ProcessCollector : BaseCollector
    {
        /// <summary>
        /// </summary>
        /// <param name="opts"> </param>
        /// <param name=""> </param>
        public ProcessCollector(CollectorOptions? opts = null, Action<CollectObject>? changeHandler = null) : base(opts, changeHandler) { }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        /// <summary>
        ///     Execute the Process collector.
        /// </summary>
        internal override void ExecuteInternal(CancellationToken cancellationToken)
        {
            Parallel.ForEach(Process.GetProcesses(), new ParallelOptions() { CancellationToken = cancellationToken }, process =>
            {
                if (ProcessObject.FromProcess(process) is ProcessObject po)
                    HandleChange(po);
            });
        }
    }
}