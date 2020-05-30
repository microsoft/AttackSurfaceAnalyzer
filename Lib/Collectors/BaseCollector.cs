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
using System.Threading;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// Base class for all collectors.
    /// </summary>
    public abstract class BaseCollector : IPlatformRunnable
    {
        public ConcurrentStack<CollectObject> Results { get; } = new ConcurrentStack<CollectObject>();
        internal CollectCommandOptions opts = new CollectCommandOptions();
        public void TryExecute()
        {
            Start();
            if (!CanRunOnPlatform())
            {
                Log.Warning(Strings.Get("Err_PlatIncompat"), GetType().ToString());
            }
            else
            {
                try
                {
                    ExecuteInternal();
                }
                catch(Exception e)
                {
                    Log.Debug("Failed to run {0} ({1}:{2})", GetType(), e.GetType(), e.Message);
                }
            }
            Stop();
        }

        public abstract bool CanRunOnPlatform();

        public abstract void ExecuteInternal();

        private Stopwatch? watch;
        private readonly Action<CollectObject>? changeHandler;

        protected BaseCollector(CollectCommandOptions? opts, Action<CollectObject>? changeHandler)
        {
            this.opts = opts ?? new CollectCommandOptions();
            this.changeHandler = changeHandler;
        }

        internal void HandleChange(CollectObject collectObject)
        {
            if (changeHandler != null)
            {
                changeHandler(collectObject);
            }
            else
            {
                Results.Push(collectObject);
            }
        }

        public RUN_STATUS RunStatus
        {
            get; private set;
        }

        public void Start()
        {
            RunStatus = RUN_STATUS.RUNNING;
            watch = Stopwatch.StartNew();
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