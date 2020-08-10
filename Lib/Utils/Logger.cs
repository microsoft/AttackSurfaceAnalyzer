// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Serilog;
using Serilog.Events;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Utils
{
    public static class Logger
    {
        public static bool Debug { get; set; }
        public static bool Quiet { get; set; }
        public static bool Verbose { get; set; }

        public static void Setup()
        {
            Setup(false, false);
        }

        public static void Setup(bool debug, bool verbose)
        {
            Setup(debug, verbose, false);
        }

        public static void Setup(bool debug, bool verbose, bool quiet)
        {
            (Verbose, Debug, Quiet) = (verbose, debug, quiet);
            if (quiet)
            {
                Log.Logger = new LoggerConfiguration()
                    .MinimumLevel.Warning()
                    .WriteTo.Console()
                    .CreateLogger();
            }
            else if (verbose)
            {
                Log.Logger = new LoggerConfiguration()
                    .MinimumLevel.Verbose()
                    .WriteTo.File("asa.log.txt")
                    .WriteTo.Console()
                    .CreateLogger();
            }
            else if (debug)
            {
                Log.Logger = new LoggerConfiguration()
                    .MinimumLevel.Debug()
                    .WriteTo.File("asa.log.txt")
                    .WriteTo.Console()
                    .CreateLogger();
            }
            else
            {
                Log.Logger = new LoggerConfiguration()
                   .MinimumLevel.Information()
                   .WriteTo.Console(restrictedToMinimumLevel: LogEventLevel.Information)
                   .CreateLogger();
            }
        }
    }
}