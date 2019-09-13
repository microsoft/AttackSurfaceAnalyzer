// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Serilog;
using Serilog.Events;
using System;

namespace AttackSurfaceAnalyzer.Utils
{
    public class Logger
    {

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

        public static void DebugException(Exception e)
        {
            Log.Debug("{0} {1} {2}", e.GetType().ToString(), e.Message, e.StackTrace);
        }

        public static void VerboseException(Exception e)
        {
            Log.Verbose("{0} {1} {2}", e.GetType().ToString(), e.Message, e.StackTrace);
        }
    }
}