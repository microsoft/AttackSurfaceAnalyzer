// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Serilog;
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Utils
{
    public static class CryptoHelpers
    {
        /// <summary>
        /// Perform a hash of a string.
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static string CreateHash(string input)
        {
            HashAlgorithm hasher = GetHasher();
            try
            {
                byte[] hashOutput = hasher.ComputeHash(Encoding.UTF8.GetBytes(input));
                return Convert.ToBase64String(hashOutput);
            }
            catch (CryptographicException e)
            {
                Log.Warning(e, Strings.Get("Err_CreateHash"), input is null ? "null string" : $"'{input}'");
                return string.Empty;
            }
            finally
            {
                ReleaseHasher(hasher);
            }
        }

        public static string CreateHash(byte[] input)
        {
            HashAlgorithm hasher = GetHasher();
            try
            {
                byte[] hashOutput = hasher.ComputeHash(input);
                return Convert.ToBase64String(hashOutput);
            }
            catch (CryptographicException e)
            {
                Log.Warning(e, Strings.Get("Err_CreateHash"), "[byte array]");
                return string.Empty;
            }
            finally
            {
                ReleaseHasher(hasher);
            }
        }

        public static string CreateHash(Stream stream)
        {
            HashAlgorithm hasher = GetHasher();
            try
            {
                return Convert.ToBase64String(hasher.ComputeHash(stream) ?? Array.Empty<byte>());
            }
            catch (CryptographicException e)
            {
                Log.Warning(e, Strings.Get("Err_CreateHash"), "stream");
                return string.Empty;
            }
            finally
            {
                ReleaseHasher(hasher);
            }
        }

        private static HashAlgorithm GetHasher()
        {
            if (hashers.TryDequeue(out HashAlgorithm? hashAlgorithm) && hashAlgorithm is { })
            {
                return hashAlgorithm;
            }
            else
            {
                return SHA512.Create();
            }
        }

        private static void ReleaseHasher(HashAlgorithm hashAlgorithm)
        {
            hashers.Enqueue(hashAlgorithm);
        }

        public static double GetRandomPositiveDouble(double max)
        {
            var bytes = RandomNumberGenerator.GetBytes(8);
            return (BitConverter.ToUInt64(bytes, 0) >> 11) / (double)ulong.MaxValue * max;
        }

        public static int GetRandomPositiveIndex(int max)
        {
            var randomInteger = uint.MaxValue;
            while (randomInteger == uint.MaxValue)
            {
                byte[] data = RandomNumberGenerator.GetBytes(4);
                randomInteger = BitConverter.ToUInt32(data, 0);
            }

            return (int)(max * (randomInteger / (double)uint.MaxValue));
        }

        public static string GetRandomString(int characters) => new(Enumerable.Range(1, characters).Select(_ => chars[GetRandomPositiveIndex(chars.Length)]).ToArray());

        private const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        private static ConcurrentQueue<HashAlgorithm> hashers = new ConcurrentQueue<HashAlgorithm>();
    }
}