// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// Base class for all collectors.
    /// </summary>
    public abstract class BaseCollector : IPlatformRunnable
    {
        public List<CollectObject> Results { get; } = new List<CollectObject>();

        public void Execute()
        {
            if (!CanRunOnPlatform())
            {
                Log.Warning(Strings.Get("Err_PlatIncompat"), GetType().ToString());
            }
            else
            {
                Start();
                ExecuteInternal();
                Stop();
            }
        }

        public abstract bool CanRunOnPlatform();

        public abstract void ExecuteInternal();

        private Stopwatch? watch;

        public RUN_STATUS RunStatus
        {
            get; private set;
        }

        public void Start()
        {
            RunStatus = RUN_STATUS.RUNNING;
            watch = System.Diagnostics.Stopwatch.StartNew();
            Log.Information(Strings.Get("Starting"), GetType().Name);
        }

        public void Stop()
        {
            RunStatus = RUN_STATUS.COMPLETED;
            watch?.Stop();
            TimeSpan t = TimeSpan.FromMilliseconds(watch?.ElapsedMilliseconds ?? 0);
            string answer = string.Format(CultureInfo.InvariantCulture, "{0:D2}h:{1:D2}m:{2:D2}s:{3:D3}ms",
                                    t.Hours,
                                    t.Minutes,
                                    t.Seconds,
                                    t.Milliseconds);
            Log.Information(Strings.Get("Completed"), GetType().Name, answer);
            var EndEvent = new Dictionary<string, string>();
            EndEvent.Add("Scanner", GetType().Name);
            EndEvent.Add("Duration", watch?.ElapsedMilliseconds.ToString(CultureInfo.InvariantCulture) ?? "");
            AsaTelemetry.TrackEvent("EndScanFunction", EndEvent);
        }
    }
}