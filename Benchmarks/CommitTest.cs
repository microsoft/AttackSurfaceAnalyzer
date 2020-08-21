using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using BenchmarkDotNet.Attributes;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Benchmarks
{
    [MarkdownExporterAttribute.GitHub]
    [JsonExporterAttribute.Full]
    public class CommitTest
    {
#nullable disable

        public CommitTest()
#nullable enable
        {
            Logger.Setup(true, true);
            Strings.Setup();
        }

        [Params("OFF", "DELETE", "WAL", "MEMORY")]
        public string JournalMode { get; set; }

        //Rows to write in the open transaction before the commit
        [Params(10000, 20000, 40000)]
        public int N { get; set; }

        // The number of Shards/Threads to use for Database operations
        [Params(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)]
        public int Shards { get; set; }

        [Benchmark]
        public void CommitTransaction()
        {
            dbManager.Commit();
        }

        [IterationCleanup]
        public void IterationCleanup()
        {
            dbManager.Destroy();
        }

        [IterationSetup]
        public void IterationSetup()
        {
            Setup();
            dbManager.BeginTransaction();
            InsertTestsWithoutTransactions.Insert_X_Objects(N, dbManager);
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

#nullable disable
    }
}