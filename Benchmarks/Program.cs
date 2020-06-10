using BenchmarkDotNet.Running;

namespace AttackSurfaceAnalyzer.Benchmarks
{
    public class Program
    {
        #region Public Methods

        public static void Main(string[] args)
        {
            var summary = BenchmarkRunner.Run<InsertTestsWithoutTransactions>();
        }

        #endregion Public Methods
    }
}