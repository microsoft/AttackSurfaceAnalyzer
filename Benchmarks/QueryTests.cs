using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using BenchmarkDotNet.Attributes;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace AttackSurfaceAnalyzer.Benchmarks
{
    [MarkdownExporterAttribute.GitHub]
    [JsonExporterAttribute.Full]
    public class QueryTests : AsaDatabaseBenchmark
    {
        // The number random records to populate the database with before the two compare runs are added
        [Params(0)]
        public int StartingSize { get; set; }

        // The amount of padding to add to the object in bytes
        // Default size is approx 530 bytes serialized
        // Does not include SQL overhead
        [Params(0)]
        public int ObjectPadding { get; set; }

        // The number of records in run one
        [Params(10000)]
        public int RunOneSize { get; set; }

        // The number of records in run two
        [Params(10000)]
        public int RunTwoSize { get; set; }

        // Percent of identities which should match between the two runs (% of the smaller run)
        [Params(0,.25,.5,.75,1)]
        public double IdentityMatches { get; set; }

        // Percent of those identities which match which should match in rowkey
        [Params(0,.25,.5,.75,1)]
        public double RowKeyMatches { get; set; }

        // The number of Shards/Threads to use for Database operations
        [Params(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)]
        public int Shards { get; set; }

        //[Params("OFF","DELETE","WAL","MEMORY")]
        [Params("WAL")]
        public string JournalMode { get; set; }

        // Options are NORMAL, EXCLUSIVE
        [Params("NORMAL")]
        public string LockingMode { get; set; }

        // Options are powers of 2 between 512 and 65536
        [Params(4096)]
        public int PageSize { get; set; }

        // Options are OFF, NORMAL, FULL, EXTRA
        [Params("OFF")]
        public string Synchronous { get; set; }

        private readonly string RunOneName = "RunOne";
        private readonly string RunTwoName = "RunTwo";

        // Bag of reusable objects to write to the database.
        private static readonly ConcurrentBag<FileSystemObject> BagOfObjects = new ConcurrentBag<FileSystemObject>();

        // Bag of reusable identities
        private static readonly ConcurrentBag<(string, string)> BagOfIdentities = new ConcurrentBag<(string, string)>();


        public QueryTests()
        {
            Logger.Setup(true, true);
            Strings.Setup();
        }

        public void InsertFirstRun()
        {
            Parallel.For(0, RunOneSize, i =>
            {
                var obj = GetRandomObject(ObjectPadding);
                DatabaseManager.Write(obj, RunOneName);

                BagOfIdentities.Add((obj.Identity, obj.FileType));
                BagOfObjects.Add(obj);
            });

            while (DatabaseManager.HasElements())
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

                DatabaseManager.Write(obj, RunTwoName);
                BagOfObjects.Add(obj);
            });
        }

        [Benchmark]
        public void GetMissingFromFirstTest()
        {
            DatabaseManager.GetMissingFromFirst(RunOneName, RunTwoName);
        }

        [Benchmark]
        public void GetModifiedTest()
        {
            DatabaseManager.GetModified(RunOneName, RunTwoName);
        }

        public void PopulateDatabases()
        {
            Setup();
            DatabaseManager.BeginTransaction();

            InsertFirstRun();
            InsertSecondRun();

            while(DatabaseManager.HasElements()){
                Thread.Sleep(1);
            }

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

        private void Setup()
        {
            DatabaseManager.Setup(filename: $"AsaBenchmark_{Shards}.sqlite", new DBSettings()
            {
                JournalMode = JournalMode,
                LockingMode = LockingMode,
                PageSize = PageSize,
                ShardingFactor = Shards,
                Synchronous = Synchronous
            });
        }

        [IterationCleanup]
        public void IterationCleanup()
        {
            DatabaseManager.CloseDatabase();
        }
    }
}
