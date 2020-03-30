using AttackSurfaceAnalyzer.Utils;
using BenchmarkDotNet.Attributes;

namespace AttackSurfaceAnalyzer.Benchmarks
{
    [MarkdownExporterAttribute.GitHub]
    [JsonExporterAttribute.Full]
    public class CommitTest
    {
        //Rows to write in the open transaction before the commit
        [Params(10000, 20000, 40000)]
        public int N { get; set; }

        // The number of Shards/Threads to use for Database operations
        [Params(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)]
        public int Shards { get; set; }

        [Params("OFF", "DELETE", "WAL", "MEMORY")]
        public string JournalMode { get; set; }

        public CommitTest()
        {
            Logger.Setup(true, true);
            Strings.Setup();
        }

        [Benchmark]
        public void CommitTransaction()
        {
            DatabaseManager.Commit();
        }

        public void Setup()
        {
            DatabaseManager.Setup(filename: $"AsaBenchmark_{Shards}.sqlite", new DBSettings()
            {
                JournalMode = JournalMode,
                ShardingFactor = Shards
            });
        }

        [IterationSetup]
        public void IterationSetup()
        {
            Setup();
            DatabaseManager.BeginTransaction();
            InsertTestsWithoutTransactions.Insert_X_Objects(N);
        }

        [IterationCleanup]
        public void IterationCleanup()
        {
            DatabaseManager.Destroy();
        }
    }
}
