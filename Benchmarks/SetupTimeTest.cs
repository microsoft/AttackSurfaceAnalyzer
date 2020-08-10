using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using BenchmarkDotNet.Attributes;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Benchmarks
{
    [MarkdownExporterAttribute.GitHub]
    [JsonExporterAttribute.Full]
    public class SetupTimeTest : AsaDatabaseBenchmark
    {
#nullable disable

        public SetupTimeTest()
#nullable restore
        {
            Logger.Setup(true, true);
            Strings.Setup();
        }

        //[Params("OFF","DELETE","WAL","MEMORY")]
        [Params("OFF", "DELETE", "WAL", "MEMORY")]
        public string JournalMode { get; set; }

        [Params("NORMAL", "EXCLUSIVE")]
        public string LockingMode { get; set; }

        // The amount of padding to add to the object in bytes Default size is approx 530 bytes serialized
        // Does not include SQL overhead
        [Params(0)]
        public int ObjectPadding { get; set; }

        [Params(4096)]
        public int PageSize { get; set; }

        // The number of Shards/Threads to use for Database operations
        [Params(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)]
        public int Shards { get; set; }

        // The number of records to populate the database with before the benchmark
        //[Params(0,100000,200000,400000,800000,1600000,3200000)]
        [Params(0, 10000000)]
        public int StartingSize { get; set; }

        [Params("OFF", "NORMAL")]
        public string Synchronous { get; set; }

        [GlobalCleanup]
        public void GlobalCleanup()
        {
            Setup();
            dbManager.Destroy();
        }

        [GlobalSetup]
        public void GlobalSetup()
        {
            PopulateDatabases();
        }

        public void Insert_X_Objects(int X, int ObjectPadding = 0, string runName = "Insert_X_Objects")
        {
            Parallel.For(0, X, i =>
            {
                var obj = GetRandomObject(ObjectPadding);
                dbManager.Write(obj, runName);
                BagOfObjects.Add(obj);
            });

            while (dbManager.HasElements)
            {
                Thread.Sleep(1);
            }
        }

        [IterationCleanup]
        public void IterationCleanup()
        {
            dbManager.CloseDatabase();
        }

        [IterationSetup]
        public void IterationSetup()
        {
        }

        public void PopulateDatabases()
        {
            Setup();
            dbManager.BeginTransaction();

            Insert_X_Objects(StartingSize, ObjectPadding, "PopulateDatabase");

            dbManager.Commit();
            dbManager.CloseDatabase();
        }

        private DatabaseManager dbManager;

        [Benchmark]
        private void Setup()
        {
            dbManager = new SqliteDatabaseManager(filename: $"AsaBenchmark_{Shards}.sqlite", new DBSettings()
            {
                JournalMode = JournalMode,
                LockingMode = LockingMode,
                PageSize = PageSize,
                ShardingFactor = Shards,
                Synchronous = Synchronous
            });

            dbManager.Setup();
        }
    }
}