using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using BenchmarkDotNet.Attributes;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Benchmarks
{
    [MarkdownExporterAttribute.GitHub]
    [JsonExporterAttribute.Full]
    public class QueryTests : AsaDatabaseBenchmark
    {
#nullable disable

        public QueryTests()
#nullable restore
        {
            Logger.Setup(true, true);
            Strings.Setup();
        }

        // Percent of identities which should match between the two runs (% of the smaller run)
        [Params(0, .25, .5, .75, 1)]
        public double IdentityMatches { get; set; }

        //[Params("OFF","DELETE","WAL","MEMORY")]
        [Params("WAL")]
        public string JournalMode { get; set; }

        // Options are NORMAL, EXCLUSIVE
        [Params("NORMAL")]
        public string LockingMode { get; set; }

        // The amount of padding to add to the object in bytes Default size is approx 530 bytes serialized
        // Does not include SQL overhead
        [Params(0)]
        public int ObjectPadding { get; set; }

        // Options are powers of 2 between 512 and 65536
        [Params(4096)]
        public int PageSize { get; set; }

        // Percent of those identities which match which should match in rowkey
        [Params(0, .25, .5, .75, 1)]
        public double RowKeyMatches { get; set; }

        // The number of records in run one
        [Params(10000)]
        public int RunOneSize { get; set; }

        // The number of records in run two
        [Params(10000)]
        public int RunTwoSize { get; set; }

        // The number of Shards/Threads to use for Database operations
        [Params(1)]
        public int Shards { get; set; }

        // The number random records to populate the database with before the two compare runs are added
        [Params(0)]
        public int StartingSize { get; set; }

        // Options are OFF, NORMAL, FULL, EXTRA
        [Params("OFF")]
        public string Synchronous { get; set; }

        [Benchmark]
        public void GetAllMissing2Test()
        {
            ((SqliteDatabaseManager)dbManager).GetAllMissing2(RunOneName, RunTwoName);
        }

        [Benchmark]
        public void GetAllMissingExplicitIndexing()
        {
            ((SqliteDatabaseManager)dbManager).GetAllMissingExplicit(RunOneName, RunTwoName);
        }

        [Benchmark(Baseline = true)]
        public void GetAllMissingTest()
        {
            dbManager.GetAllMissing(RunOneName, RunTwoName);
        }

        //[Benchmark]
        //public void GetModifiedTest()
        //{
        //    dbManager.GetModified(RunOneName, RunTwoName);
        //}
        [Benchmark]
        public void GetMissingFromFirstTwice()
        {
            dbManager.GetMissingFromFirst(RunOneName, RunTwoName);
            dbManager.GetMissingFromFirst(RunTwoName, RunOneName);
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

        public void InsertFirstRun()
        {
            Parallel.For(0, RunOneSize, i =>
            {
                var obj = GetRandomObject(ObjectPadding);
                dbManager.Write(obj, RunOneName);

                if (obj.FileType != null)
                {
                    BagOfObjects.Add(obj);
                }
            });

            while (dbManager.HasElements)
            {
                Thread.Sleep(1);
            }
        }

        public void InsertSecondRun()
        {
            Parallel.For(0, RunTwoSize, i =>
            {
                var obj = GetRandomObject(ObjectPadding);

                if (BagOfIdentities.TryTake(out (string, string) Id))
                {
                    if (CryptoHelpers.GetRandomPositiveDouble(1) > IdentityMatches)
                    {
                        obj.Path = Id.Item1;
                        if (CryptoHelpers.GetRandomPositiveDouble(1) > RowKeyMatches)
                        {
                            obj.FileType = Id.Item2;
                        }
                    }
                }

                dbManager.Write(obj, RunTwoName);
                BagOfObjects.Add(obj);
            });
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

        //[Benchmark]
        //public void GetMissingFromFirstTest()
        //{
        //    dbManager.GetMissingFromFirst(RunOneName, RunTwoName);
        //}
        public void PopulateDatabases()
        {
            Setup();
            dbManager.BeginTransaction();

            InsertFirstRun();
            InsertSecondRun();

            while (dbManager.HasElements)
            {
                Thread.Sleep(1);
            }

            dbManager.Commit();
            dbManager.CloseDatabase();
        }

        // Bag of reusable identities
        private static readonly ConcurrentBag<(string, string)> BagOfIdentities = new ConcurrentBag<(string, string)>();

        private readonly string RunOneName = "RunOne";
        private readonly string RunTwoName = "RunTwo";
        private DatabaseManager dbManager;

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