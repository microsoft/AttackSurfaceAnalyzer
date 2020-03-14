using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using BenchmarkDotNet.Attributes;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace AttackSurfaceAnalyzer.Benchmarks
{
    [MarkdownExporterAttribute.GitHub]
    [JsonExporterAttribute.Full]
    public class LiteDbInsertTests : AsaDatabaseBenchmark
    {
        // The number of records to insert for the benchmark
        //[Params(25000,50000,100000)]
        [Params(10000)]
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
        //[Params(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)]
        [Params(1)]
        public int Shards { get; set; }

        // Bag of reusable objects to write to the database.
        private static readonly ConcurrentBag<FileSystemObject> BagOfObjects = new ConcurrentBag<FileSystemObject>();

        public LiteDbInsertTests()
        {
            Logger.Setup(true, true);
            Strings.Setup();
        }

        [Benchmark]
        public void Insert_N_Objects() => Insert_X_Objects(N, ObjectPadding, "Insert_N_Objects");

        public static void Insert_X_Objects(int X, int ObjectPadding = 0, string runName = "Insert_X_Objects")
        {
            Parallel.For(0, X, i =>
            {
                var obj = GetRandomObject(ObjectPadding);
                LiteDbManager.Write(obj, runName);
                BagOfObjects.Add(obj);
            });

            while (LiteDbManager.HasElements())
            {
                Thread.Sleep(1);
            }
        }

        public void PopulateDatabases()
        {
            Setup();
            LiteDbManager.BeginTransaction();

            Insert_X_Objects(StartingSize, ObjectPadding, "PopulateDatabase");

            LiteDbManager.Commit();
            LiteDbManager.CloseDatabase();
        }

        [GlobalSetup]
        public void GlobalSetup()
        {
            PopulateDatabases();
        }

        [GlobalCleanup]
        public void GlobalCleanup()
        {
            Setup();
            LiteDbManager.Destroy();
        }

        [IterationSetup]
        public void IterationSetup()
        {
            Setup();
            LiteDbManager.BeginTransaction();
        }

        private void Setup()
        {
            LiteDbManager.Setup(filename: $"AsaBenchmark_{Shards}.litedb");
        }

        [IterationCleanup]
        public void IterationCleanup()
        {
            LiteDbManager.CloseDatabase();
        }
    }
}
