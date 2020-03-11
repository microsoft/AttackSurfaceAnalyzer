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
        public static string CreateHash(string input)
        {
            if (input == null)
            {
                return null;
            }

            using HashAlgorithm murmur128 = MurmurHash.Create128();
            byte[] hashOutput = murmur128.ComputeHash(Encoding.UTF8.GetBytes(input));
            return Convert.ToBase64String(hashOutput);
        }

        public static byte[] CreateHash(byte[] input)
        {
            if (input == null)
            {
                return null;
            }
            using HashAlgorithm murmur128 = MurmurHash.Create128();
            return murmur128.ComputeHash(input);
        }

        public static string CreateHash(FileStream stream)
        {
            using HashAlgorithm murmur128 = MurmurHash.Create128();
            return Convert.ToBase64String(murmur128.ComputeHash(stream));
        }

        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        private readonly static RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider();

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

    }
}