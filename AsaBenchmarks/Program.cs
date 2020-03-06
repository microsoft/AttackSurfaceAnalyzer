
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using AttackSurfaceAnalyzer.Utils;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using Serilog;

namespace AttackSurfaceAnalyzer.Benchmarks
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Logger.Setup(true, true);
            Strings.Setup();

            var summary = BenchmarkRunner.Run<InsertTests>();

            //var InsertTests = new InsertTests();
            //InsertTests.N = 10000;
            //var MaxThreads = 12;
            //var Iterations = 100;

            //var results = new List<List<TimeSpan>>();

            //for (int threads = 1; threads < MaxThreads; threads++)
            //{
            //    Log.Information($"Running {threads} shards.");
            //    results.Add(new List<TimeSpan>());
            //    for (int i = 0; i < Iterations; i++)
            //    {
            //        DatabaseManager.Setup(filename: "AsaBenchmark.sqlite", shardingFactor: threads);

            //        var StopWatch = System.Diagnostics.Stopwatch.StartNew();

            //        InsertTests.RunInsertTest();

            //        StopWatch.Stop();

            //        DatabaseManager.Destroy();

            //        TimeSpan t = TimeSpan.FromMilliseconds(StopWatch.ElapsedMilliseconds);

            //        string answer = string.Format(CultureInfo.InvariantCulture, "{0:D2}h:{1:D2}m:{2:D2}s:{3:D3}ms",
            //            t.Hours,
            //            t.Minutes,
            //            t.Seconds,
            //            t.Milliseconds);
            //        Log.Information("Completed in {0}", answer);
            //        results[threads - 1].Add(t);
            //    }
            //}
            Log.Information(Utf8Json.JsonSerializer.ToJsonString(summary));
        }
    }
}
