using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using BenchmarkDotNet.Attributes;
using Murmur;
using Serilog;
using System.Collections.Concurrent;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Policy;
using System.Threading;
using System.Threading.Tasks;
using Utf8Json;

namespace AttackSurfaceAnalyzer.Benchmarks
{
    [MarkdownExporterAttribute.GitHub]
    [JsonExporterAttribute.Full]
    public class CryptoTests : AsaDatabaseBenchmark
    {
        // The amount of padding to add to the object in bytes
        // Default size is approx 530 bytes serialized
        // Does not include SQL overhead
        [Params(0)]
        public int ObjectPadding { get; set; }

        // The number of iterations per run
        [Params(100000)]
        public int N { get; set; }

        static HashAlgorithm murmur128 = MurmurHash.Create128();
        static HashAlgorithm sha256 = SHA256.Create();

        static HashAlgorithm sha512 = SHA512.Create();

        private ConcurrentQueue<byte[]> hashObjects = new ConcurrentQueue<byte[]>();

#nullable disable
        public CryptoTests()
#nullable restore
        {
            
        }

        [Benchmark (Baseline = true)]
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


        [GlobalSetup]
        public void GlobalSetup()
        {
            while (hashObjects.Count < N)
            {
                hashObjects.Enqueue(JsonSerializer.Serialize<FileSystemObject>(GetRandomObject(ObjectPadding)));
            }
        }
    }
}
