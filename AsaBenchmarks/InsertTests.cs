using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using BenchmarkDotNet.Attributes;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AttackSurfaceAnalyzer.Benchmarks
{
    public class InsertTests
    {
        [Params(10000)]
        public int N { get; set; }

        [Params(0)]
        public int StartingSize { get; set; }

        [Params(0, 50, 100, 200, 300)]
        public int ObjectSize { get; set; }

        [Params(12)]
        public int Shards { get; set; }

        // Bag of reusable objects to write to the database.
        private readonly ConcurrentBag<FileSystemObject> BagOfObjects = new ConcurrentBag<FileSystemObject>();
        private readonly Random rnd = new Random();

        public InsertTests()
        {
            Logger.Setup(true, true);
            Strings.Setup();
        }

        [Benchmark]
        public void Insert_N_Objects()
        {
            Parallel.For(0, N, i =>
            {
                var obj = GetRandomObject();
                DatabaseManager.Write(obj, $"InsertTest_Sharding");
                BagOfObjects.Add(obj);
            });

            while (DatabaseManager.HasElements())
            {
                Thread.Sleep(1);
            }

        }

        [Benchmark]
        public FileSystemObject GetRandomObject()
        {
            BagOfObjects.TryTake(out FileSystemObject obj);

            if (obj != null)
            {
                obj.Path = $"/bin/AttackSurfaceAnalyzer_{rnd.Next()}";
                return obj;
            }
            else
            {
                return new FileSystemObject()
                {
                    Characteristics = new List<string>() { "One", "Two", "Three", "Four" },
                    // Pad this field with extra data.  The ObjectSize parameter determines the size of this data.
                    FileType = Enumerable.Repeat("a", ObjectSize).ToString(),
                    Group = "Wheel",
                    IsDirectory = false,
                    IsExecutable = true,
                    IsLink = false,
                    Owner = "Microsoft",
                    Path = $"/bin/AttackSurfaceAnalyzer_{rnd.Next()}",
                    Permissions = new Dictionary<string, string>() { { "Owner", "ReadWriteExecute" }, { "Group", "ReadWriteExecute" }, { "Everyone", "ReadWriteExecute" } },
                    PermissionsString = "This is a fake permissions string",
                    SetGid = false,
                    SetUid = false,
                    ResultType = Types.RESULT_TYPE.FILE,
                    SignatureStatus = new Signature() { IsAuthenticodeValid = false },
                    Size = 300
                };
            }
        }

        public void PopulateDatabases()
        {
            DatabaseManager.BeginTransaction();

            Parallel.For(0, N, i =>
            {
                DatabaseManager.Write(GetRandomObject(), $"InsertTest_Sharding");
            });

            while (DatabaseManager.HasElements())
            {
                Thread.Sleep(100);
            }

            DatabaseManager.Commit();
        }

        [GlobalSetup]
        public void GlobalSetup()
        {
            DatabaseManager.Setup(filename: $"AsaBenchmark_{Shards}.sqlite", shardingFactor: Shards);
            PopulateDatabases();
            DatabaseManager.CloseDatabase();
        }

        [GlobalCleanup]
        public void GlobalCleanup()
        {
            DatabaseManager.Destroy();
        }

        [IterationSetup]
        public void IterationSetup()
        {
            DatabaseManager.Setup(filename: $"AsaBenchmark_{Shards}.sqlite", shardingFactor: Shards);
            DatabaseManager.BeginTransaction();
        }

        [IterationCleanup]
        public void IterationCleanup()
        {
            DatabaseManager.RollBack();
            DatabaseManager.CloseDatabase();
        }
    }
}
