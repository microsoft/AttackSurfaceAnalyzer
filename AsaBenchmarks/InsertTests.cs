using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using BenchmarkDotNet.Attributes;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace AttackSurfaceAnalyzer.Benchmarks
{
    [MarkdownExporterAttribute.GitHub]
    [JsonExporterAttribute.Full]
    public class InsertTests
    {
        // The number of records to insert for the benchmark
        [Params(10000)]
        public int N { get; set; }

        // The number of records to populate the database with before the benchmark
        //[Params(0,100000,200000,400000,800000,1600000,3200000)]
        [Params(0,400000)]
        public int StartingSize { get; set; }

        // The amount of padding to add to the object in bytes
        // Default size is approx 530 bytes serialized
        // Does not include SQL overhead
        [Params(0)]
        public int ObjectSize { get; set; }

        // The number of Shards/Threads to use for Database operations
        //[Params(1,2,3,4,5,6,7,8,9,10,12)]
        [Params(4,12)]
        public int Shards { get; set; }

        // Bag of reusable objects to write to the database.
        private readonly ConcurrentBag<FileSystemObject> BagOfObjects = new ConcurrentBag<FileSystemObject>();

        public InsertTests()
        {
            Logger.Setup(true, true);
            Strings.Setup();
        }

        [Benchmark]
        public void Insert_N_Objects() => Insert_X_Objects(N);
        
        public void Insert_X_Objects(int X)
        {
            DatabaseManager.BeginTransaction();

            Parallel.For(0, X, i =>
            {
                var obj = GetRandomObject();
                DatabaseManager.Write(obj, $"Insert_N_Objects");
                BagOfObjects.Add(obj);
            });

            while (DatabaseManager.HasElements())
            {
                Thread.Sleep(1);
            }

            DatabaseManager.Commit();
        }

        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        const int length = 64;

        public string GetRandomString(int characters) => new string(Enumerable.Range(1, characters).Select(_ => chars[GetRandomPositiveIndex(chars.Length)]).ToArray());

        public int GetRandomPositiveIndex(int max)
        {
            using (RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider())
            {
                byte[] data = new byte[4];
                crypto.GetBytes(data);
                var randomInteger = Math.Abs(BitConverter.ToInt32(data, 0));
                return randomInteger % max;
            }
        }

        public FileSystemObject GetRandomObject()
        {
            BagOfObjects.TryTake(out FileSystemObject obj);

            if (obj != null)
            {
                obj.Path = GetRandomString(length);
                return obj;
            }
            else
            {
                return new FileSystemObject()
                {
                    // Pad this field with extra data.
                    FileType = GetRandomString(ObjectSize),
                    Path = GetRandomString(length)
                };
            }
        }

        public void PopulateDatabases()
        {
            DatabaseManager.Setup(filename: $"AsaBenchmark_{Shards}.sqlite", shardingFactor: Shards);

            Insert_X_Objects(StartingSize);

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
            DatabaseManager.Setup(filename: $"AsaBenchmark_{Shards}.sqlite", shardingFactor: Shards);
            DatabaseManager.Destroy();
        }

        [IterationSetup]
        public void IterationSetup()
        {
            DatabaseManager.Setup(filename: $"AsaBenchmark_{Shards}.sqlite", shardingFactor: Shards);
        }

        [IterationCleanup]
        public void IterationCleanup()
        {
            DatabaseManager.DeleteRun("Insert_N_Objects");
            DatabaseManager.CloseDatabase();
        }
    }
}
