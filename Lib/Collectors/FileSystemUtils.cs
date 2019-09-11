// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Utils;
using Serilog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace AttackSurfaceAnalyzer.Collectors
{
    public class FileSystemUtils
    {
        protected internal static string GetFilePermissions(FileSystemInfo fileInfo)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return WindowsFileSystemUtils.GetFilePermissions(fileInfo);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                return LinuxFileSystemUtils.GetFilePermissions(fileInfo);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return LinuxFileSystemUtils.GetFilePermissions(fileInfo);
            }
            else
            {
                return null;
            }
        }

        protected internal static string GetFileOwner(FileSystemInfo fileInfo)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return null;
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                return LinuxFileSystemUtils.GetFilePermissions(fileInfo);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return LinuxFileSystemUtils.GetFilePermissions(fileInfo);
            }
            else
            {
                return null;
            }
        }

        protected internal static string GetFileHash(FileSystemInfo fileInfo)
        {
            Log.Debug("{0} {1}", Strings.Get("FileHash"), fileInfo.FullName);

            string hashValue = null;
            try
            {
                using (var stream = new FileStream(fileInfo.FullName, FileMode.Open, FileAccess.Read))
                {
                    hashValue = CryptoHelpers.CreateHash(stream);
                }
            }
            catch (Exception ex)
            {
                Log.Warning("{0}: {1} {2}", Strings.Get("Err_UnableToHash"), fileInfo.FullName, ex.Message);
            }
            return hashValue;
        }

        public static KeyValuePair<bool, X509Certificate2> GetSignatureDetails(string path)
        {
            if (path == null)
            {
                return new KeyValuePair<bool, X509Certificate2>(false, null);
            }

            if (!File.Exists(path))
            {
                return new KeyValuePair<bool, X509Certificate2>(false, null);
            }

            X509Certificate2 certificate = null;
            try
            {
                certificate = new X509Certificate2(X509Certificate2.CreateFromSignedFile(path));
                if (!certificate.Verify())
                {
                    return new KeyValuePair<bool, X509Certificate2>(false, certificate);
                }
                if (!certificate.IssuerName.Name.Contains("Microsoft"))
                {
                    return new KeyValuePair<bool, X509Certificate2>(false, certificate);
                }
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "{0} {1}: {2}", Strings.Get("Err_ExceptionCheckSig"), path, ex.Message);
                return new KeyValuePair<bool, X509Certificate2>(false, certificate);
            }

            return new KeyValuePair<bool, X509Certificate2>(true, certificate);
        }
    }
}