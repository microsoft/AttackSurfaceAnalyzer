using BenchmarkDotNet.Attributes;
using Murmur;
using Newtonsoft.Json;
using Serilog;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Benchmarks
{
    [MarkdownExporterAttribute.GitHub]
    [JsonExporterAttribute.Full]
    public class CryptoTests : AsaDatabaseBenchmark
    {
        public CryptoTests()
        {
        }

        // The number of iterations per run
        [Params(100000)]
        public int N { get; set; }

        // The number of iterations per run
        [Params(1000)]
        public int NumObjects { get; set; }

        // The amount of padding to add to the object in bytes Default size is approx 530 bytes serialized
        // Does not include SQL overhead
        [Params(1000)]
        public int ObjectPadding { get; set; }

        [Benchmark]
        public void Generate_N_Murmur_Hashes()
        {
            for (int i = 0; i < N; i++)
            {
                hashObjects.TryDequeue(out byte[]? result);
                if (result is byte[])
                {
                    _ = murmur128.ComputeHash(result);
                    hashObjects.Enqueue(result);
                }
                else
                {
                    Log.Information("The queue is polluted with nulls");
                }
            }
        }

        [Benchmark(Baseline = true)]
        public void Generate_N_SHA256_Hashes()
        {
            for (int i = 0; i < N; i++)
            {
                hashObjects.TryDequeue(out byte[]? result);
                if (result is byte[])
                {
                    _ = sha256.ComputeHash(result);
                    hashObjects.Enqueue(result);
                }
                else
                {
                    Log.Information("The queue is polluted with nulls");
                }
            }
        }

        [Benchmark]
        public void Generate_N_SHA256Managed_Hashes()
        {
            for (int i = 0; i < N; i++)
            {
                hashObjects.TryDequeue(out byte[]? result);
                if (result is byte[])
                {
                    _ = sha256managed.ComputeHash(result);
                    hashObjects.Enqueue(result);
                }
                else
                {
                    Log.Information("The queue is polluted with nulls");
                }
            }
        }

        [Benchmark]
        public void Generate_N_SHA512_Hashes()
        {
            for (int i = 0; i < N; i++)
            {
                hashObjects.TryDequeue(out byte[]? result);
                if (result is byte[])
                {
                    _ = sha512.ComputeHash(result);
                    hashObjects.Enqueue(result);
                }
                else
                {
                    Log.Information("The queue is polluted with nulls");
                }
            }
        }

        [Benchmark]
        public void Generate_N_SHA512_Managed_Hashes()
        {
            for (int i = 0; i < N; i++)
            {
                hashObjects.TryDequeue(out byte[]? result);
                if (result is byte[])
                {
                    _ = sha512managed.ComputeHash(result);
                    hashObjects.Enqueue(result);
                }
                else
                {
                    Log.Information("The queue is polluted with nulls");
                }
            }
        }

        [GlobalSetup]
        public void GlobalSetup()
        {
            while (hashObjects.Count < NumObjects)
            {
                hashObjects.Enqueue(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(GetRandomObject(ObjectPadding))));
            }
        }

        private static readonly HashAlgorithm murmur128 = MurmurHash.Create128();

        private static readonly HashAlgorithm sha256 = SHA256.Create();

        private static readonly HashAlgorithm sha256managed = SHA256Managed.Create();

        private static readonly HashAlgorithm sha512 = SHA512.Create();

        private static readonly HashAlgorithm sha512managed = SHA512Managed.Create();

        private readonly ConcurrentQueue<byte[]> hashObjects = new ConcurrentQueue<byte[]>();
    }
}