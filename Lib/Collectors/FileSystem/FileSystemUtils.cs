// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AttackSurfaceAnalyzer.Utils;
using Murmur;

namespace AttackSurfaceAnalyzer.Collectors.FileSystem
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
            else
            {
                return null;
            }
        }

        protected internal static string GetFileHash(FileSystemInfo fileInfo)
        {
            Logger.Instance.Debug("Generating file hash for {0}", fileInfo.FullName);

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
                Logger.Instance.Warn("Unable to take hash of file: {0}: {1}", fileInfo.FullName, ex.Message);
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
            catch(Exception ex)
            {
                Logger.Instance.Debug(ex, "Exception checking for file signature for {0}: {1}", path, ex.Message);
                return new KeyValuePair<bool, X509Certificate2>(false, certificate);
            }

            return new KeyValuePair<bool, X509Certificate2>(true, certificate);
        }
    }
}