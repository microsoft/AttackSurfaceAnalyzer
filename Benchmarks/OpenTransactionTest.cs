using AttackSurfaceAnalyzer.Utils;
using BenchmarkDotNet.Attributes;

namespace AttackSurfaceAnalyzer.Benchmarks
{
    [MarkdownExporterAttribute.GitHub]
    [JsonExporterAttribute.Full]
    public class OpenTransactionTest : AsaDatabaseBenchmark
    {
        // The number of records to populate the database with before the benchmark
        //[Params(0,100000,200000,400000,800000,1600000,3200000)]
        [Params(0)]
        public int StartingSize { get; set; }

        // The number of Shards/Threads to use for Database operations
        [Params(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)]
        public int Shards { get; set; }

        [Params("OFF", "DELETE", "WAL", "MEMORY")]
        public string JournalMode { get; set; }

        public OpenTransactionTest()
        {
            Logger.Setup(true, true);
            Strings.Setup();
        }

        [Benchmark]
        public void BeginTransaction()
        {
            DatabaseManager.BeginTransaction();
        }

        public void Setup()
        {
            DatabaseManager.Setup(filename: $"AsaBenchmark_{Shards}.sqlite", new DBSettings()
            {
                JournalMode = JournalMode,
                ShardingFactor = Shards
            });
        }

        public void PopulateDatabases()
        {
            Setup();
            DatabaseManager.BeginTransaction();

            InsertTestsWithoutTransactions.Insert_X_Objects(StartingSize);

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
            Setup();
            DatabaseManager.Destroy();
        }

        [IterationSetup]
        public void IterationSetup()
        {
            Setup();
        }

        [IterationCleanup]
        public void IterationCleanup()
        {
            DatabaseManager.CloseDatabase();
        }
    }
}
