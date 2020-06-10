using AttackSurfaceAnalyzer.Utils;
using BenchmarkDotNet.Attributes;

namespace AttackSurfaceAnalyzer.Benchmarks
{
    [MarkdownExporterAttribute.GitHub]
    [JsonExporterAttribute.Full]
    public class CommitTest
    {
        #region Public Constructors

        public CommitTest()
#nullable enable
        {
            Logger.Setup(true, true);
            Strings.Setup();
        }

        #endregion Public Constructors

        #region Public Properties

        [Params("OFF", "DELETE", "WAL", "MEMORY")]
        public string JournalMode { get; set; }

        //Rows to write in the open transaction before the commit
        [Params(10000, 20000, 40000)]
        public int N { get; set; }

        // The number of Shards/Threads to use for Database operations
        [Params(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)]
        public int Shards { get; set; }

        #endregion Public Properties

#nullable disable

        #region Public Methods

        [Benchmark]
        public void CommitTransaction()
        {
            DatabaseManager.Commit();
        }

        [IterationCleanup]
        public void IterationCleanup()
        {
            DatabaseManager.Destroy();
        }

        [IterationSetup]
        public void IterationSetup()
        {
            Setup();
            DatabaseManager.BeginTransaction();
            InsertTestsWithoutTransactions.Insert_X_Objects(N);
        }

        public void Setup()
        {
            DatabaseManager.Setup(filename: $"AsaBenchmark_{Shards}.sqlite", new DBSettings()
            {
                JournalMode = JournalMode,
                ShardingFactor = Shards
            });
        }

        #endregion Public Methods
    }
}