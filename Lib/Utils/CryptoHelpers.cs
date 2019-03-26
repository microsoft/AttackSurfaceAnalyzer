using System;
using System.Data.HashFunction.xxHash;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Murmur;

namespace AttackSurfaceAnalyzer.Utils
{
    public class CryptoHelpers
    {
        public static string CreateHash(string input)
        {
            if (input == null)
            {
                return null;
            }

            HashAlgorithm murmur128 = MurmurHash.Create128();
            byte[] hashOutput = murmur128.ComputeHash(Encoding.UTF8.GetBytes(input));
            return Convert.ToBase64String(hashOutput);
        }

        public static string CreateHash(FileStream stream)
        {
            HashAlgorithm murmur128 = MurmurHash.Create128();
            return Convert.ToBase64String(murmur128.ComputeHash(stream));
        }

    }
}