// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using Serilog;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// Collects metadata from the local certificate stores.
    /// </summary>
    public class CertificateCollector : BaseCollector
    {
        public CertificateCollector(string runId)
        {
            RunId = runId;
        }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        /// <summary>
        /// On Windows we can use the .NET API to iterate through all the stores.
        /// </summary>
        public void ExecuteWindows()
        {
            foreach (StoreLocation storeLocation in (StoreLocation[])Enum.GetValues(typeof(StoreLocation)))
            {
                foreach (StoreName storeName in (StoreName[])Enum.GetValues(typeof(StoreName)))
                {
                    try
                    {
                        using X509Store store = new X509Store(storeName, storeLocation);
                        store.Open(OpenFlags.ReadOnly);

                        foreach (X509Certificate2 certificate in store.Certificates)
                        {
                            var obj = new CertificateObject(
                                StoreLocation: storeLocation.ToString(),
                                StoreName: storeName.ToString(),
                                Certificate: new SerializableCertificate(certificate))
                            {
                                Pkcs7 = Convert.ToBase64String(certificate.Export(X509ContentType.Cert))
                            };
                            DatabaseManager.Write(obj, RunId);
                        }

                        store.Close();
                    }
                    catch (CryptographicException e)
                    {
                        Log.Debug(e, $"Error parsing a certificate in {storeLocation} {storeName}");
                    }
                }
            }
        }

        /// <summary>
        /// On linux we check the central trusted root store (a folder), which has symlinks to actual cert locations scattered across the db
        /// We list all the certificates and then create a new X509Certificate2 object for each by filename.
        /// </summary>
        public void ExecuteLinux()
        {
            try
            {
                if (ExternalCommandRunner.RunExternalCommand("ls", "/etc/ssl/certs -A", out string result, out string _) == 0)
                {
                    foreach (var _line in result.Split('\n'))
                    {
                        Log.Debug("{0}", _line);
                        try
                        {
                            using X509Certificate2 certificate = new X509Certificate2("/etc/ssl/certs/" + _line);

                            var obj = new CertificateObject(
                                StoreLocation: StoreLocation.LocalMachine.ToString(),
                                StoreName: StoreName.Root.ToString(),
                                Certificate: new SerializableCertificate(certificate))
                            {
                                Pkcs7 = Convert.ToBase64String(certificate.Export(X509ContentType.Cert))
                            };

                            DatabaseManager.Write(obj, RunId);
                        }
                        catch (Exception e)
                        {
                            Log.Debug("{0} {1} Issue creating certificate based on /etc/ssl/certs/{2}", e.GetType().ToString(), e.Message, _line);
                            Log.Debug("{0}", e.StackTrace);

                        }
                    }
                }
            }
            catch (Exception e)
            {
                Log.Error(e, "Failed to dump certificates from 'ls /etc/ssl/certs -A'.");
            }
        }

        /// <summary>
        /// On macos we use the keychain and export the certificates as .pem.
        /// However, on macos Certificate2 doesn't support loading from a pem.
        /// So first we need pkcs12s instead, we convert using openssl, which requires we set a password
        /// we import the pkcs12 with all our certs, delete the temp files and then iterate over it the certs
        /// </summary>
        public void ExecuteMacOs()
        {
            try
            {
                if (ExternalCommandRunner.RunExternalCommand("security", "find-certificate -ap /System/Library/Keychains/SystemRootCertificates.keychain", out string result, out string _) == 0)
                {
                    string tmpPath = Path.Combine(Directory.GetCurrentDirectory(), "tmpcert.pem");
                    string pkPath = Path.Combine(Directory.GetCurrentDirectory(), "tmpcert.pk12");

                    File.WriteAllText(tmpPath, result);
                    if (ExternalCommandRunner.RunExternalCommand("openssl", $"pkcs12 -export -nokeys -out {pkPath} -passout pass:pass -in {tmpPath}",out string _, out string _) == 0)
                    {
                        X509Certificate2Collection xcert = new X509Certificate2Collection();
                        xcert.Import(pkPath, "pass", X509KeyStorageFlags.DefaultKeySet); //lgtm [cs/hardcoded-credentials]

                        File.Delete(tmpPath);
                        File.Delete(pkPath);

                        var X509Certificate2Enumerator = xcert.GetEnumerator();

                        while (X509Certificate2Enumerator.MoveNext())
                        {
                            var certificate = X509Certificate2Enumerator.Current;

                            var obj = new CertificateObject(
                                StoreLocation: StoreLocation.LocalMachine.ToString(),
                                StoreName: StoreName.Root.ToString(),
                                Certificate: new SerializableCertificate(certificate))
                            {
                                Pkcs7 = Convert.ToBase64String(certificate.Export(X509ContentType.Cert))
                            };
                            DatabaseManager.Write(obj, RunId);
                        }
                    }
                    else
                    {
                        Log.Debug("Failed to export certificate with OpenSSL.");
                    }
                }
                
            }
            catch (Exception e)
            {
                Log.Error("Failed to dump certificates from 'security' or 'openssl'.");
                Log.Debug(e, "ExecuteMacOs()");
            }
        }

        /// <summary>
        /// Execute the certificate collector.
        /// </summary>
        public override void ExecuteInternal()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                ExecuteWindows();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                ExecuteLinux();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                ExecuteMacOs();
            }
        }
    }
}