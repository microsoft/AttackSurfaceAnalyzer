// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using Serilog;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Threading;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// Base class for all collectors.
    /// </summary>
    public abstract class BaseCollector : IPlatformRunnable
    {
        public string RunId { get; set; } = "";

        private RUN_STATUS _running = RUN_STATUS.NOT_STARTED;

        private readonly int _numCollected = 0;

        public void Execute()
        {
            if (!CanRunOnPlatform())
            {
                Log.Warning(string.Format(CultureInfo.InvariantCulture, Strings.Get("Err_PlatIncompat"), GetType().ToString()));
                return;
            }
            Start();

            DatabaseManager.BeginTransaction();

            var StopWatch = System.Diagnostics.Stopwatch.StartNew();

            ExecuteInternal();

            StopWatch.Stop();
            TimeSpan t = TimeSpan.FromMilliseconds(StopWatch.ElapsedMilliseconds);
            string answer = string.Format(CultureInfo.InvariantCulture, "{0:D2}h:{1:D2}m:{2:D2}s:{3:D3}ms",
                                    t.Hours,
                                    t.Minutes,
                                    t.Seconds,
                                    t.Milliseconds);
            Log.Debug(Strings.Get("Completed"), GetType().Name, answer);

            var prevFlush = DatabaseManager.Connections.Select(x => x.WriteQueue.Count).Sum();
            var totFlush = prevFlush;

            var printInterval = 10;
            var currentInterval = 0;

            StopWatch = System.Diagnostics.Stopwatch.StartNew();

            while (DatabaseManager.HasElements())
            {
                Thread.Sleep(1000);

                if (currentInterval++ % printInterval == 0)
                {
                    var actualDuration = (currentInterval < printInterval) ? currentInterval : printInterval;
                    var sample = DatabaseManager.Connections.Select(x => x.WriteQueue.Count).Sum();
                    var curRate = prevFlush - sample;
                    var totRate = (double)(totFlush - sample) / StopWatch.ElapsedMilliseconds;
                    try
                    {
                        t = (curRate > 0) ? TimeSpan.FromMilliseconds(sample / ((double)curRate / (actualDuration * 1000))) : TimeSpan.FromMilliseconds(99999999);
                        answer = string.Format(CultureInfo.InvariantCulture, "{0:D2}h:{1:D2}m:{2:D2}s:{3:D3}ms",
                                                t.Hours,
                                                t.Minutes,
                                                t.Seconds,
                                                t.Milliseconds);
                        Log.Debug("Flushing {0} results. ({1}/{4}s {2:0.00}/s overall {3} ETA)", sample, curRate, totRate * 1000, answer, actualDuration);
                    }
                    catch (Exception e) when (
                        e is OverflowException)
                    {
                        Log.Debug($"Overflowed: {curRate} {totRate} {sample} {t} {answer}");
                        Log.Debug("Flushing {0} results. ({1}/s {2:0.00}/s)", sample, curRate, totRate * 1000);
                    }
                    prevFlush = sample;
                }

            }

            StopWatch.Stop();
            t = TimeSpan.FromMilliseconds(StopWatch.ElapsedMilliseconds);
            answer = string.Format(CultureInfo.InvariantCulture, "{0:D2}h:{1:D2}m:{2:D2}s:{3:D3}ms",
                                    t.Hours,
                                    t.Minutes,
                                    t.Seconds,
                                    t.Milliseconds);
            Log.Debug("Completed flushing in {0}", answer);

            DatabaseManager.Commit();
            Stop();
        }
        public abstract bool CanRunOnPlatform();

        public abstract void ExecuteInternal();

        private Stopwatch? watch;

        public RUN_STATUS IsRunning()
        {
            return _running;
        }

        public void Start()
        {
            _running = RUN_STATUS.RUNNING;
            watch = System.Diagnostics.Stopwatch.StartNew();

            Log.Information(Strings.Get("Starting"), GetType().Name);
        }

        public void Stop()
        {
            _running = RUN_STATUS.COMPLETED;
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
            EndEvent.Add("NumResults", _numCollected.ToString(CultureInfo.InvariantCulture));
            AsaTelemetry.TrackEvent("EndScanFunction", EndEvent);
        }

        public int NumCollected()
        {
            return _numCollected;
        }
    }
}