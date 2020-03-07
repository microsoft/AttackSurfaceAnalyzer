using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using BenchmarkDotNet.Attributes;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace AttackSurfaceAnalyzer.Benchmarks
{
    [MarkdownExporterAttribute.GitHub]
    [JsonExporterAttribute.Full]
    public class InsertTests
    {
        // The number of records to insert for the benchmark
        [Params(10000, 100000)]
        public int N { get; set; }

        // The number of records to populate the database with before the benchmark
        [Params(0,1000000)]
        public int StartingSize { get; set; }

        // The amount of padding to add to the object in bytes
        // Default size is approx 530 bytes serialized
        [Params(0)]
        public int ObjectSize { get; set; }

        // The number of Shards/Threads to use for Database operations
        [Params(12)]
        public int Shards { get; set; }

        // Bag of reusable objects to write to the database.
        private readonly ConcurrentBag<FileSystemObject> BagOfObjects = new ConcurrentBag<FileSystemObject>();
        private readonly Random rnd = new Random();

        public InsertTests()
        {
            Logger.Setup(true, true);
            Strings.Setup();
        }

        [Benchmark]
        public void Insert_N_Objects()
        {
            DatabaseManager.BeginTransaction();

            Parallel.For(0, N, i =>
            {
                var obj = GetRandomObject();
                DatabaseManager.Write(obj, $"Insert_N_Objects");
                BagOfObjects.Add(obj);
            });

            while (DatabaseManager.HasElements())
            {
                Thread.Sleep(1);
            }

            DatabaseManager.Commit();
        }

        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        const int length = 50;
        private static Random random = new Random();

        public string GetRandomString(int characters)
        {
            return Enumerable.Range(1, characters).Select(_ => chars[random.Next(chars.Length)]).ToString();
        }

        public FileSystemObject GetRandomObject()
        {
            BagOfObjects.TryTake(out FileSystemObject obj);

            if (obj != null)
            {
                obj.Path = GetRandomString(length);
                return obj;
            }
            else
            {
                return new FileSystemObject()
                {
                    // Pad this field with extra data.
                    FileType = GetRandomString(ObjectSize),
                    Path = GetRandomString(length)
                };
            }
        }

        public void PopulateDatabases()
        {
            DatabaseManager.Setup(filename: $"AsaBenchmark_{Shards}.sqlite", shardingFactor: Shards);
            DatabaseManager.BeginTransaction();

            Parallel.For(0, N, i =>
            {
                DatabaseManager.Write(GetRandomObject(), $"PopulateDatabases");
            });

            while (DatabaseManager.HasElements())
            {
                Thread.Sleep(10);
            }
            DatabaseManager.Commit();
            DatabaseManager.CloseDatabase();
        }

        [GlobalSetup]
        public void GlobalSetup()
        {
            PopulateDatabases();
        }

        [GlobalCleanup]
        public void GlobalCleanup()
        {
            DatabaseManager.Destroy();
        }

        [IterationSetup]
        public void IterationSetup()
        {
            DatabaseManager.Setup(filename: $"AsaBenchmark_{Shards}.sqlite", shardingFactor: Shards);
        }

        [IterationCleanup]
        public void IterationCleanup()
        {
            DatabaseManager.DeleteRun("Insert_N_Objects");
            DatabaseManager.CloseDatabase();
        }
    }
}
