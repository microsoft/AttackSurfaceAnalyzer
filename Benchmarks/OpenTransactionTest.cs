using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using BenchmarkDotNet.Attributes;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Benchmarks
{
    [MarkdownExporterAttribute.GitHub]
    [JsonExporterAttribute.Full]
    public class OpenTransactionTest : AsaDatabaseBenchmark
    {
#nullable disable

        public OpenTransactionTest()
#nullable restore
        {
            Logger.Setup(true, true);
            Strings.Setup();
        }

        [Params("OFF", "DELETE", "WAL", "MEMORY")]
        public string JournalMode { get; set; }

        // The number of Shards/Threads to use for Database operations
        [Params(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)]
        public int Shards { get; set; }

        // The number of records to populate the database with before the benchmark
        //[Params(0,100000,200000,400000,800000,1600000,3200000)]
        [Params(0)]
        public int StartingSize { get; set; }

        [Benchmark]
        public void BeginTransaction()
        {
            dbManager.BeginTransaction();
        }

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

        [IterationCleanup]
        public void IterationCleanup()
        {
            dbManager.CloseDatabase();
        }

        [IterationSetup]
        public void IterationSetup()
        {
            Setup();
        }

        public void PopulateDatabases()
        {
            Setup();
            dbManager.BeginTransaction();

            InsertTestsWithoutTransactions.Insert_X_Objects(StartingSize, dbManager, 0, "Insert_X_Objects");

            dbManager.Commit();
            dbManager.CloseDatabase();
        }

        public void Setup()
        {
            dbManager = new SqliteDatabaseManager(filename: $"AsaBenchmark_{Shards}.sqlite", new DBSettings()
            {
                JournalMode = JournalMode,
                ShardingFactor = Shards
            });
            dbManager.Setup();
        }

        private DatabaseManager dbManager;
    }
}