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
        [Params(10000, 25000)]
        public int N { get; set; }

        [Params(1, 4)]
        public int Shards { get; set; }

        public InsertTests()
        {
            Strings.Setup();
        }

        [Benchmark]
        public void RunInsertTest()
        {
            DatabaseManager.BeginTransaction();

            Parallel.For(0, N, i =>
            {
                DatabaseManager.Write(new FileSystemObject()
                {
                    Characteristics = new List<string>() { "One", "Two", "Three", "Four" },
                    FileType = $"{i}",
                    Group = "Wheel",
                    IsDirectory = false,
                    IsExecutable = true,
                    IsLink = false,
                    Owner = "Microsoft",
                    Path = "/bin/AttackSurfaceAnalyzer",
                    Permissions = new Dictionary<string, string>() { { "Owner", "ReadWriteExecute" }, { "Group", "ReadWriteExecute" }, { "Everyone", "ReadWriteExecute" } },
                    PermissionsString = "This is a fake permissions string",
                    SetGid = false,
                    SetUid = false,
                    ResultType = Types.RESULT_TYPE.FILE,
                    SignatureStatus = new Signature() { IsAuthenticodeValid = false },
                    Size = 300
                }, $"InsertTest_Sharding");
            });

            while (DatabaseManager.HasElements())
            {
                Thread.Sleep(1);
            }

            DatabaseManager.Commit();
        }

        [IterationSetup]
        public void IterationSetup() => DatabaseManager.Setup(filename: "AsaBenchmark.sqlite", shardingFactor: Shards);

        [IterationCleanup]
        public void IterationCleanup() => DatabaseManager.Destroy();

    }
}
