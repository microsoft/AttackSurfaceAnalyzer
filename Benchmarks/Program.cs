using BenchmarkDotNet.Running;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Benchmarks
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var summary = BenchmarkRunner.Run<CryptoTests>();
        }
    }
}