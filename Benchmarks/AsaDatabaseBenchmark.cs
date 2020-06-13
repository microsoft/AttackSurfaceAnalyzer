using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using System.Collections.Concurrent;

namespace AttackSurfaceAnalyzer.Benchmarks
{
    public class AsaDatabaseBenchmark
    {
        // Bag of reusable objects to write to the database.
        public static readonly ConcurrentBag<FileSystemObject> BagOfObjects = new ConcurrentBag<FileSystemObject>();

        public static FileSystemObject GetRandomObject(int ObjectPadding = 0)
        {
            BagOfObjects.TryTake(out FileSystemObject? obj);

            if (obj != null)
            {
                obj.Path = CryptoHelpers.GetRandomString(32);
                return obj;
            }
            else
            {
                return new FileSystemObject(CryptoHelpers.GetRandomString(32))
                {
                    // Pad this field with extra data.
                    FileType = CryptoHelpers.GetRandomString(ObjectPadding),
                };
            }
        }
    }
}