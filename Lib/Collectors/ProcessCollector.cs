// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using Serilog;
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// Collects metadata from the local certificate stores.
    /// </summary>
    public class ProcessCollector : BaseCollector
    {
        /// <summary>
        /// </summary>
        /// <param name="opts"></param>
        /// <param name=""></param>
        public ProcessCollector(CollectCommandOptions? opts = null, Action<CollectObject>? changeHandler = null) : base(opts, changeHandler) { }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        /// <summary>
        /// Execute the certificate collector.
        /// </summary>
        internal override void ExecuteInternal(CancellationToken cancellationToken)
        {
            Process[] allProcesses = Process.GetProcesses();
            foreach (var process in allProcesses)
            {
                HandleChange(ProcessObject.FromProcess(process));
            }
        }
    }
}