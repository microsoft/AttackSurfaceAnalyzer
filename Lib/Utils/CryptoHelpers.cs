﻿// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
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
        public static string CreateHash(string input)
        {
            try
            {
                byte[] hashOutput = sha512.ComputeHash(Encoding.UTF8.GetBytes(input));
                return Convert.ToBase64String(hashOutput);
            }
            catch (CryptographicException e)
            {
                Log.Warning(e, Strings.Get("Err_CreateHash"), "string");
                return string.Empty;
            }
        }

        public static byte[] CreateHash(byte[] input)
        {
            try
            {
                return sha512.ComputeHash(input);
            }
            catch (CryptographicException e)
            {
                Log.Warning(e, Strings.Get("Err_CreateHash"), "bytes");
                return Array.Empty<byte>();
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
            var bytes = new byte[8];
            crypto.GetBytes(bytes);
            return (BitConverter.ToUInt64(bytes, 0) >> 11) / (double)ulong.MaxValue * max;
        }

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

        public static string GetRandomString(int characters) => new string(Enumerable.Range(1, characters).Select(_ => chars[GetRandomPositiveIndex(chars.Length)]).ToArray());

        private const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        private static readonly RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider();

        // These are not intended to be cryptographically secure hashes These are used as a uniqueness check
        private static readonly HashAlgorithm sha512 = SHA512.Create();
    }
}