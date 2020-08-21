using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using BenchmarkDotNet.Attributes;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Benchmarks
{
    [MarkdownExporterAttribute.GitHub]
    [JsonExporterAttribute.Full]
    public class SystemSqliteInsertTestsWithoutTransactions : AsaDatabaseBenchmark
    {
#nullable disable

        public SystemSqliteInsertTestsWithoutTransactions()
#nullable restore
        {
            Logger.Setup(true, true);
            Strings.Setup();
        }

        //[Params("OFF","DELETE","WAL","MEMORY")]
        [Params("WAL")]
        public string JournalMode { get; set; }

        [Params("NORMAL")]
        public string LockingMode { get; set; }

        // The number of records to insert for the benchmark
        //[Params(25000,50000,100000)]
        [Params(10000)]
        public int N { get; set; }

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
        [Params(0)]
        public int StartingSize { get; set; }

        [Params("OFF")]
        public string Synchronous { get; set; }

        public static void Insert_X_Objects(int X, int ObjectPadding = 0, string runName = "Insert_X_Objects")
        {
            Parallel.For(0, X, i =>
            {
                var obj = GetRandomObject(ObjectPadding);
                SystemSQLiteDatabaseManager.Write(obj, runName);
                BagOfObjects.Add(obj);
            });

            while (SystemSQLiteDatabaseManager.HasElements())
            {
                Thread.Sleep(1);
            }
        }

        [GlobalCleanup]
        public void GlobalCleanup()
        {
            Setup();
            SystemSQLiteDatabaseManager.Destroy();
        }

        [GlobalSetup]
        public void GlobalSetup()
        {
            PopulateDatabases();
        }

        [Benchmark]
        public void Insert_N_Objects() => Insert_X_Objects(N, ObjectPadding, "Insert_N_Objects");

        [IterationCleanup]
        public void IterationCleanup()
        {
            SystemSQLiteDatabaseManager.CloseDatabase();
        }

        [IterationSetup]
        public void IterationSetup()
        {
            Setup();
            SystemSQLiteDatabaseManager.BeginTransaction();
        }

        public void PopulateDatabases()
        {
            Setup();
            SystemSQLiteDatabaseManager.BeginTransaction();

            Insert_X_Objects(StartingSize, ObjectPadding, "PopulateDatabase");

            SystemSQLiteDatabaseManager.Commit();
            SystemSQLiteDatabaseManager.CloseDatabase();
        }

        private void Setup()
        {
            SystemSQLiteDatabaseManager.Setup(filename: $"AsaBenchmark_{Shards}.sqlite", new DBSettings()
            {
                JournalMode = JournalMode,
                LockingMode = LockingMode,
                PageSize = PageSize,
                ShardingFactor = Shards,
                Synchronous = Synchronous
            });
        }
    }
}