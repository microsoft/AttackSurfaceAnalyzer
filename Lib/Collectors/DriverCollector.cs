// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Medallion.Shell;
using Serilog;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Collectors
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
        public DriverCollector(CollectorOptions? opts = null, Action<CollectObject>? changeHandler = null) : base(opts, changeHandler) { }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
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
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                ExecuteMacOs(cancellationToken);
            }
        }

        private void ExecuteLinux(CancellationToken cancellationToken)
        {
            var command = Command.Run("lsmod");
            command.Wait();
            var result = command.Result;

            if (result != null)
            {
                var lines = result.StandardOutput.Split(Environment.NewLine)[1..];
                Parallel.ForEach(lines, new ParallelOptions() { CancellationToken = cancellationToken }, driverLine =>
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        return;
                    }

                    var driverLineSplits = driverLine.Split(' ');
                    var innerCommand = Command.Run("modinfo", driverLineSplits[0]);
                    innerCommand.Wait();
                    var innerResult = innerCommand.Result;

                    if (innerResult != null)
                    {
                        var modInfoLines = innerResult.StandardOutput.Split(Environment.NewLine);
                        var modInfoDict = new Dictionary<string, string>();

                        foreach (var modInfoLine in modInfoLines)
                        {
                            var lineSplit = modInfoLine.Split(' ');
                            modInfoDict[lineSplit[0].Trim(':')] = lineSplit[1];
                        }

                        // TODO: Extract more of these properties into their own fields
                        var obj = new DriverObject(modInfoDict["filename"])
                        {
                            Description = modInfoDict["description"],
                            Version = modInfoDict["srcversion"],
                            Properties = modInfoDict,
                            Size = driverLineSplits[1],
                            LinkedAgainst = driverLineSplits.Length > 3 ? driverLineSplits[3].Split(',').ToList() : null
                        };

                        HandleChange(obj);
                    }
                });
            }
        }

        private void ExecuteMacOs(CancellationToken cancellationToken)
        {
            var command = Command.Run("kextstat", "-a", "-l");

            command.Wait();
            var result = command.Result;

            var results = new List<DriverObject>();
            if (result != null)
            {
                foreach (var driverLine in result.StandardOutput.Split(Environment.NewLine).Where(x => !string.IsNullOrEmpty(x)))
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        return;
                    }
                    try
                    {
                        string[] parts = driverLine.Split(' ').Where(x => !string.IsNullOrEmpty(x)).ToArray();
                        int[] links = parts.Length > 9 ? parts[9..].Select(x => int.Parse(x.Replace("<", "").Replace(">", ""), CultureInfo.InvariantCulture)).ToArray() : Array.Empty<int>();
                        var obj = new DriverObject(parts[6])
                        {
                            Index = int.Parse(parts[0], CultureInfo.InvariantCulture),
                            Refs = int.Parse(parts[1], CultureInfo.InvariantCulture),
                            Address = parts[2],
                            Size = parts[3],
                            Wired = parts[4],
                            Architecture = parts[5],
                            Version = parts[7].Trim('(').Trim(')'),
                            UUID = parts[8],
                            LinkedAgainst = results.Where(x => links.Any(y => y == x.Index)).Select(x => x.Identity).ToList()
                        };
                        HandleChange(obj);
                        results.Add(obj);
                    }
                    catch (Exception e)
                    {
                        Log.Debug("Failed to parse {0}. ({1}:{2})", driverLine, e.GetType(), e.Message);
                    }
                }
            }
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
                    if (parts.Length >= 15)
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
                            Init = long.Parse(parts[14].Replace(",", ""), CultureInfo.InvariantCulture),
                            Signature = WindowsFileSystemUtils.GetSignatureStatus(parts[13])
                        });
                });
            }
        }
    }
}