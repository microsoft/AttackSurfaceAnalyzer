using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using BenchmarkDotNet.Attributes;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
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
        [Params(10000)]
        public int N { get; set; }

        // The number of records to populate the database with before the benchmark
        [Params(0,100000,200000,300000,400000,500000,600000,700000,800000,900000,1000000)]
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
            Parallel.For(0, N, i =>
            {
                var obj = GetRandomObject();
                DatabaseManager.Write(obj, $"InsertTest_Sharding");
                BagOfObjects.Add(obj);
            });

            while (DatabaseManager.HasElements())
            {
                Thread.Sleep(1);
            }

        }

        public FileSystemObject GetRandomObject()
        {
            BagOfObjects.TryTake(out FileSystemObject obj);

            if (obj != null)
            {
                obj.Path = $"/bin/AttackSurfaceAnalyzer_{rnd.Next()}";
                return obj;
            }
            else
            {
                return new FileSystemObject()
                {
                    // Pad this field with extra data.  The ObjectSize parameter determines the size of this data.
                    FileType = Enumerable.Repeat("a", ObjectSize).ToString(),
                    Path = $"/bin/AttackSurfaceAnalyzer_{rnd.Next()}",
                };
            }
        }

        public void PopulateDatabases()
        {
            DatabaseManager.Setup(filename: $"AsaBenchmark_{Shards}.sqlite", shardingFactor: Shards);
            DatabaseManager.BeginTransaction();

            Parallel.For(0, N, i =>
            {
                DatabaseManager.Write(GetRandomObject(), $"InsertTest_Sharding");
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
            DatabaseManager.BeginTransaction();
        }

        [IterationCleanup]
        public void IterationCleanup()
        {
            DatabaseManager.CloseDatabase();
        }
    }
}
