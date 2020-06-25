// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using Medallion.Shell;
using System;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    ///     Collects metadata about processes on the local computer.
    /// </summary>
    public class DriverCollector : BaseCollector
    {
        /// <summary>
        /// </summary>
        /// <param name="opts"> </param>
        /// <param name=""> </param>
        public DriverCollector(CollectCommandOptions? opts = null, Action<CollectObject>? changeHandler = null) : base(opts, changeHandler) { }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        }

        /// <summary>
        ///     Execute the Process collector.
        /// </summary>
        internal override void ExecuteInternal(CancellationToken cancellationToken)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                ExecuteWindows(cancellationToken);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                ExecuteLinux(cancellationToken);
            }
        }

        private void ExecuteLinux(CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        private void ExecuteWindows(CancellationToken cancellationToken)
        {
            var command = Command.Run("driverquery", "/FO", "CSV", "/NH", "/V");

            command.Wait();
            var result = command.Result;
            if (result != null)
            {
                Parallel.ForEach(result.StandardOutput.Split(Environment.NewLine), new ParallelOptions() { CancellationToken = cancellationToken }, driverLine =>
                {
                    var parts = driverLine.Split('"').Where(x => x != ",").ToArray()[1..];
                    HandleChange(new DriverObject(parts[0])
                    {
                        DisplayName = parts[1],
                        Description = parts[2],
                        DriverType = parts[3],
                        StartMode = parts[4],
                        State = parts[5],
                        Status = parts[6],
                        AcceptStop = bool.Parse(parts[7]),
                        AcceptPause = bool.Parse(parts[8]),
                        PagedPool = long.Parse(parts[9].Replace(",", ""), CultureInfo.InvariantCulture),
                        Code = long.Parse(parts[10].Replace(",", ""), CultureInfo.InvariantCulture),
                        BSS = long.Parse(parts[11].Replace(",", ""), CultureInfo.InvariantCulture),
                        LinkDate = string.IsNullOrEmpty(parts[12]) ? DateTime.MinValue : DateTime.Parse(parts[12], CultureInfo.InvariantCulture),
                        Path = parts[13],
                        Init = long.Parse(parts[14].Replace(",", ""), CultureInfo.InvariantCulture)
                    });
                });
            }
        }
    }
}