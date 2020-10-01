// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Threading;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    ///     Base class for all collectors.
    /// </summary>
    public abstract class BaseCollector : IPlatformRunnable
    {
        public ConcurrentStack<CollectObject> Results { get; } = new ConcurrentStack<CollectObject>();

        public RUN_STATUS RunStatus
        {
            get; private set;
        }

        public abstract bool CanRunOnPlatform();

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
        }

        public void TryExecute(CancellationToken? token = null)
        {
            var cancellationToken = token is CancellationToken cancelToken ? cancelToken : GetPlaceholderToken();
            Start();
            if (!CanRunOnPlatform())
            {
                Log.Warning(Strings.Get("Err_PlatIncompat"), GetType().ToString());
            }
            else
            {
                try
                {
                    ExecuteInternal(cancellationToken);
                }
                catch (Exception e)
                {
                    Log.Debug("Failed to run {0} ({1}:{2})", GetType(), e.GetType(), e.Message);
                }
            }
            Stop();
        }

        internal CollectorOptions opts = new CollectorOptions();

        internal abstract void ExecuteInternal(CancellationToken cancellationToken);

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

        protected BaseCollector(CollectorOptions? opts, Action<CollectObject>? changeHandler)
        {
            this.opts = opts ?? new CollectorOptions();
            this.changeHandler = changeHandler;
        }

        private readonly Action<CollectObject>? changeHandler;
        
        private Stopwatch? watch;

        private static CancellationToken GetPlaceholderToken()
        {
            using var source = new CancellationTokenSource();
            return source.Token;
        }
    }
}