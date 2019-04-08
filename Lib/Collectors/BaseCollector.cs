// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using AttackSurfaceAnalyzer.ObjectTypes;
using AttackSurfaceAnalyzer.Utils;
using Serilog;

namespace AttackSurfaceAnalyzer.Collectors
{
    public abstract class BaseCollector : PlatformRunnable
    {
        protected string runId = null;

        private RUN_STATUS _running = RUN_STATUS.NOT_STARTED;

        protected int _numCollected = 0;

        public abstract void Execute();

        public abstract bool CanRunOnPlatform();

        private Stopwatch watch;

        public RUN_STATUS IsRunning()
        {
            return _running;
        }

        public void Start()
        {
            _running = RUN_STATUS.RUNNING;
            watch = System.Diagnostics.Stopwatch.StartNew();

            Log.Information("Executing {0}.", this.GetType().Name);
        }

        public void Stop()
        {
            _running = RUN_STATUS.COMPLETED;
            watch.Stop();
            TimeSpan t = TimeSpan.FromMilliseconds(watch.ElapsedMilliseconds);
            string answer = string.Format("{0:D2}h:{1:D2}m:{2:D2}s:{3:D3}ms",
                                    t.Hours,
                                    t.Minutes,
                                    t.Seconds,
                                    t.Milliseconds);
            Log.Information("Completed {0} in {1}", this.GetType().Name, answer);
            Log.Debug(t.ToString());
            var EndEvent = new Dictionary<string, string>();
            EndEvent.Add("Scanner", this.GetType().Name);
            EndEvent.Add("Duration", watch.ElapsedMilliseconds.ToString());
            EndEvent.Add("NumResults", _numCollected.ToString());
            Telemetry.TrackEvent("EndScanFunction", EndEvent);
        }

        public int NumCollected()
        {
            return _numCollected;
        }

        public BaseCollector()
        {
            
        }
    }
}