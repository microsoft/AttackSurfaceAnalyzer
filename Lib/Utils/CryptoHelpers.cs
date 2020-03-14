// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using Murmur;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AttackSurfaceAnalyzer.Utils
{
    public static class CryptoHelpers
    {
        // These are not intended to be cryptographically secure hashes
        // These are used as a uniqueness check
        static HashAlgorithm murmur128 = MurmurHash.Create128();

        public static string CreateHash(string input)
        {
            byte[] hashOutput = murmur128.ComputeHash(Encoding.UTF8.GetBytes(input));
            return Convert.ToBase64String(hashOutput);
        }

        public static byte[] CreateHash(byte[] input)
        {
            return murmur128.ComputeHash(input);
        }

        public static string CreateHash(FileStream stream)
        {
            return Convert.ToBase64String(murmur128.ComputeHash(stream) ?? Array.Empty<byte>());
        }

        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        private static readonly RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider();

        public static string GetRandomString(int characters) => new string(Enumerable.Range(1, characters).Select(_ => chars[GetRandomPositiveIndex(chars.Length)]).ToArray());

        public static int GetRandomPositiveIndex(int max)
        {
            var randomInteger = UInt32.MaxValue;
            while (randomInteger == UInt32.MaxValue)
            {
                byte[] data = new byte[4];
                crypto.GetBytes(data);
                randomInteger = BitConverter.ToUInt32(data, 0);
            }

            return (int)(max * (randomInteger / (double)uint.MaxValue));
        }

        public static double GetRandomPositiveDouble(double max)
        {
            var bytes = new byte[8];
            crypto.GetBytes(bytes);
            return (BitConverter.ToUInt64(bytes, 0) >> 11) / ulong.MaxValue * max;
        }

    }
}