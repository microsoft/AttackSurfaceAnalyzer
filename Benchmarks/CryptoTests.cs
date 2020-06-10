using BenchmarkDotNet.Attributes;
using Murmur;
using Newtonsoft.Json;
using Serilog;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace AttackSurfaceAnalyzer.Benchmarks
{
    [MarkdownExporterAttribute.GitHub]
    [JsonExporterAttribute.Full]
    public class CryptoTests : AsaDatabaseBenchmark
    {
        #region Private Fields

        private static readonly HashAlgorithm murmur128 = MurmurHash.Create128();

        private static readonly HashAlgorithm sha256 = SHA256.Create();

        private static readonly HashAlgorithm sha512 = SHA512.Create();

        private readonly ConcurrentQueue<string> hashObjects = new ConcurrentQueue<string>();

        #endregion Private Fields

        #region Public Constructors

        public CryptoTests()
#nullable restore
        {
        }

        #endregion Public Constructors

        #region Public Properties

        // The number of iterations per run
        [Params(100000)]
        public int N { get; set; }

        // The amount of padding to add to the object in bytes Default size is approx 530 bytes
        // serialized Does not include SQL overhead
        [Params(0)]
        public int ObjectPadding { get; set; }

        #endregion Public Properties

#nullable disable

        #region Public Methods

        [Benchmark]
        public void Generate_N_Murmur_Hashes()
        {
            for (int i = 0; i < N; i++)
            {
                hashObjects.TryDequeue(out string? result);
                if (result is string)
                {
                    _ = murmur128.ComputeHash(Encoding.UTF8.GetBytes(result));
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
                hashObjects.TryDequeue(out string? result);
                if (result is string)
                {
                    _ = sha256.ComputeHash(Encoding.UTF8.GetBytes(result));
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
                hashObjects.TryDequeue(out string? result);
                if (result is string)
                {
                    _ = sha512.ComputeHash(Encoding.UTF8.GetBytes(result));
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
                hashObjects.Enqueue(JsonConvert.SerializeObject(GetRandomObject(ObjectPadding)));
            }
        }

        #endregion Public Methods
    }
}