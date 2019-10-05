// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using Murmur;
using System;
using System.IO;
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

        public static string CreateHash(FileStream stream)
        {
            using HashAlgorithm murmur128 = MurmurHash.Create128();
            return Convert.ToBase64String(murmur128.ComputeHash(stream));
        }

    }
}