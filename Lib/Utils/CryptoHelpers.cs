// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Serilog;
using System;
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
            try
            {
                byte[] hashOutput = sha512.ComputeHash(Encoding.UTF8.GetBytes(input));
                return Convert.ToBase64String(hashOutput);
            }
            catch (CryptographicException e)
            {
                Log.Warning(e, Strings.Get("Err_CreateHash"), input is null ? "null string" : $"'{input}'");
                return string.Empty;
            }
        }
        
        public static string CreateHash(byte[] input)
        {
            try
            {
                byte[] hashOutput = sha512.ComputeHash(input);
                return Convert.ToBase64String(hashOutput);
            }
            catch (CryptographicException e)
            {
                Log.Warning(e, Strings.Get("Err_CreateHash"), input is null ? "null string" : $"'{input}'");
                return string.Empty;
            }
        }

        public static string CreateHash(Stream stream)
        {
            try
            {
                return Convert.ToBase64String(sha512.ComputeHash(stream) ?? Array.Empty<byte>());
            }
            catch (CryptographicException e)
            {
                Log.Warning(e, Strings.Get("Err_CreateHash"), "stream");
                return string.Empty;
            }
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

        private static readonly HashAlgorithm sha512 = SHA512.Create();
    }
}