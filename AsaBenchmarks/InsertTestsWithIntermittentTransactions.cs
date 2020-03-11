using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using BenchmarkDotNet.Attributes;
using Serilog;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace AttackSurfaceAnalyzer.Benchmarks
{
    [MarkdownExporterAttribute.GitHub]
    [JsonExporterAttribute.Full]
    public class InsertTestsWithIntermittentTransactions
    {
        // The number of records to insert for the benchmark
        //[Params(25000,50000,100000)]
        [Params(100000,1000000)]
        public int N { get; set; }

        // The number of records to populate the database with before the benchmark
        //[Params(0,100000,200000,400000,800000,1600000,3200000)]
        [Params(0)]
        public int StartingSize { get; set; }

        // The amount of padding to add to the object in bytes
        // Default size is approx 530 bytes serialized
        // Does not include SQL overhead
        [Params(0)]
        public int ObjectPadding { get; set; }

        // The number of Shards/Threads to use for Database operations
        [Params(6)]
        public int Shards { get; set; }

        // The number of Shards/Threads to use for Database operations
        [Params(5000,10000,25000,100000,-1)]
        public int FlushCount { get; set; }

        // Bag of reusable objects to write to the database.
        private static readonly ConcurrentBag<FileSystemObject> BagOfObjects = new ConcurrentBag<FileSystemObject>();

        public InsertTestsWithIntermittentTransactions()
        {
            Logger.Setup(true, true);
            Strings.Setup();
        }

        [Benchmark]
        public void Insert_N_Objects() => Insert_X_Objects(N, ObjectPadding, "Insert_N_Objects");

        public static void Insert_X_Objects(int X, int ObjectPadding = 0, string runName = "Insert_X_Objects")
        {
            DatabaseManager.BeginTransaction();

            Parallel.For(0, X, i =>
            {
                var obj = GetRandomObject(ObjectPadding);
                DatabaseManager.Write(obj, runName);
                BagOfObjects.Add(obj);
            });

            while (DatabaseManager.HasElements())
            {
                Thread.Sleep(1);
            }

            DatabaseManager.Commit();
        }

        public static FileSystemObject GetRandomObject(int ObjectPadding = 0)
        {
            BagOfObjects.TryTake(out FileSystemObject obj);

            if (obj != null)
            {
                obj.Path = CryptoHelpers.GetRandomString(32);
                return obj;
            }
            else
            {
                return new FileSystemObject()
                {
                    // Pad this field with extra data.
                    FileType = CryptoHelpers.GetRandomString(ObjectPadding),
                    Path = CryptoHelpers.GetRandomString(32)
                };
            }
        }

        public void PopulateDatabases()
        {
            DatabaseManager.Setup(filename: $"AsaBenchmark_{Shards}.sqlite", shardingFactor: Shards);

            Insert_X_Objects(StartingSize,ObjectPadding,"PopulateDatabase");

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
            DatabaseManager.Setup(filename: $"AsaBenchmark_{Shards}.sqlite", shardingFactor: Shards);
            DatabaseManager.Destroy();
        }

        [IterationSetup]
        public void IterationSetup()
        {
            DatabaseManager.Setup(filename: $"AsaBenchmark_{Shards}.sqlite", shardingFactor: Shards, flushCount: FlushCount);
        }

        [IterationCleanup]
        public void IterationCleanup()
        {
            DatabaseManager.BeginTransaction();
            DatabaseManager.DeleteRun("Insert_N_Objects");
            DatabaseManager.Commit();
            DatabaseManager.Vacuum();
            DatabaseManager.CloseDatabase();
        }
    }
}
