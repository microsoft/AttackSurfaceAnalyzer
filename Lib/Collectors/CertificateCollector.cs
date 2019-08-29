// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using AttackSurfaceAnalyzer.Utils;
using System.Security.Cryptography.X509Certificates;
using Serilog;
using AttackSurfaceAnalyzer.Objects;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// Collects metadata from the local certificate stores.
    /// </summary>
    public class CertificateCollector : BaseCollector
    {
        private bool gatherFromFiles = false;

        public CertificateCollector(string runId, bool gatherFromFiles)
        {
            this.runId = runId;
            this.gatherFromFiles = gatherFromFiles;
        }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        public override void Execute()
        {
            if (!CanRunOnPlatform())
            {
                return;
            }

            Start();

            if (gatherFromFiles)
            {
                var roots = new List<string>();
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    foreach (var driveInfo in DriveInfo.GetDrives())
                    {
                        if (driveInfo.IsReady && driveInfo.DriveType == DriveType.Fixed)
                        {
                            roots.Add(driveInfo.Name);
                        }
                    }
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    roots.Add("/");   // @TODO Improve this
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    roots.Add("/"); // @TODO Improve this
                }
                foreach (var root in roots)
                {

                    var fileInfoEnumerable = DirectoryWalker.WalkDirectory(root);
                    Parallel.ForEach(fileInfoEnumerable,
                                    (fileInfo =>
                                    {
                                        try
                                        {
                                            if (fileInfo is DirectoryInfo)
                                            {
                                                return;
                                            }
                                            // TODO: Broaden this catch
                                            if (fileInfo.FullName.EndsWith(".cer", StringComparison.CurrentCulture))
                                            {
                                                var certificate = X509Certificate.CreateFromCertFile(fileInfo.FullName);
                                                var obj = new CertificateObject()
                                                {
                                                    StoreLocation = fileInfo.FullName,
                                                    StoreName = "Disk",
                                                    CertificateHashString = certificate.GetCertHashString(),
                                                    Subject = certificate.Subject,
                                                    Pkcs12 = certificate.Export(X509ContentType.Pkcs12).ToString()
                                                };
                                                DatabaseManager.Write(obj, this.runId);
                                            }
                                        }
                                        catch (Exception e)
                                        {
                                            Log.Debug("Couldn't parse certificate file {0}", fileInfo.FullName);
                                            Log.Debug("{0} {1}-{2}",e.GetType().ToString(), e.Message, e.StackTrace);
                                        }
                                    }));


                }
            }

            // On Windows we can use the .NET API to iterate through all the stores.
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                foreach (StoreLocation storeLocation in (StoreLocation[])Enum.GetValues(typeof(StoreLocation)))
                {
                    foreach (StoreName storeName in (StoreName[])Enum.GetValues(typeof(StoreName)))
                    {
                        try
                        {
                            X509Store store = new X509Store(storeName, storeLocation);
                            store.Open(OpenFlags.ReadOnly);

                            foreach (X509Certificate2 certificate in store.Certificates)
                            {
                                var obj = new CertificateObject()
                                {
                                    StoreLocation = storeLocation.ToString(),
                                    StoreName = storeName.ToString(),
                                    CertificateHashString = certificate.GetCertHashString(),
                                    Subject = certificate.Subject,
                                    Pkcs12 = certificate.HasPrivateKey ? "redacted" : certificate.Export(X509ContentType.Pkcs12).ToString()
                                };
                                DatabaseManager.Write(obj, this.runId);
                            }
                            store.Close();
                        }
                        catch (Exception e)
                        {
                            Logger.DebugException(e);
                            Telemetry.TrackTrace(Microsoft.ApplicationInsights.DataContracts.SeverityLevel.Error, e);
                        }
                    }
                }
            }
            // On linux we check the central trusted root store (a folder), which has symlinks to actual cert locations scattered across the db
            // We list all the certificates and then create a new X509Certificate2 object for each by filename.
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                try
                {
                    var result = ExternalCommandRunner.RunExternalCommand("ls", new string[] { "/etc/ssl/certs", "-A" });

                    foreach (var _line in result.Split('\n'))
                    {
                        Log.Debug("{0}", _line);
                        try
                        {
                            X509Certificate2 certificate = new X509Certificate2("/etc/ssl/certs/" + _line);

                            var obj = new CertificateObject()
                            {
                                StoreLocation = StoreLocation.LocalMachine.ToString(),
                                StoreName = StoreName.Root.ToString(),
                                CertificateHashString = certificate.GetCertHashString(),
                                Subject = certificate.Subject,
                                Pkcs12 = certificate.HasPrivateKey ? "redacted" : certificate.Export(X509ContentType.Pkcs12).ToString()
                            };
                            DatabaseManager.Write(obj, this.runId);
                        }
                        catch (Exception e)
                        {
                            Log.Debug("{0} {1} Issue creating certificate based on /etc/ssl/certs/{2}", e.GetType().ToString(), e.Message, _line);
                            Log.Debug("{0}", e.StackTrace);

                        }
                    }
                }
                catch (Exception e)
                {
                    Log.Error("Failed to dump certificates from 'ls /etc/ssl/certs -A'.");
                    Logger.DebugException(e);
                }
                
            }
            // On macos we use the keychain and export the certificates as .pem.
            // However, on macos Certificate2 doesn't support loading from a pem, 
            // so first we need pkcs12s instead, we convert using openssl, which requires we set a password
            // we import the pkcs12 with all our certs, delete the temp files and then iterate over it the certs
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {

                try
                {
                    var result = ExternalCommandRunner.RunExternalCommand("security", new string[] { "find-certificate", "-ap", "/System/Library/Keychains/SystemRootCertificates.keychain" });
                    string tmpPath = Path.Combine(Directory.GetCurrentDirectory(), "tmpcert.pem");
                    string pkPath = Path.Combine(Directory.GetCurrentDirectory(), "tmpcert.pk12");

                    File.WriteAllText(tmpPath, result);
                    _ = ExternalCommandRunner.RunExternalCommand("openssl", new string[] { "pkcs12", "-export", "-nokeys", "-out", pkPath, "-passout pass:pass", "-in", tmpPath });

                    X509Certificate2Collection xcert = new X509Certificate2Collection();
                    xcert.Import(pkPath, "pass", X509KeyStorageFlags.DefaultKeySet);

                    File.Delete(tmpPath);
                    File.Delete(pkPath);

                    var X509Certificate2Enumerator = xcert.GetEnumerator();

                    while (X509Certificate2Enumerator.MoveNext())
                    {
                        var obj = new CertificateObject()
                        {
                            StoreLocation = StoreLocation.LocalMachine.ToString(),
                            StoreName = StoreName.Root.ToString(),
                            CertificateHashString = X509Certificate2Enumerator.Current.GetCertHashString(),
                            Subject = X509Certificate2Enumerator.Current.Subject,
                            Pkcs12 = X509Certificate2Enumerator.Current.HasPrivateKey ? "redacted" : X509Certificate2Enumerator.Current.Export(X509ContentType.Pkcs12).ToString()
                        };
                        DatabaseManager.Write(obj, this.runId);
                    }
                }
                catch(Exception e)
                {
                    Log.Error("Failed to dump certificates from 'security' or 'openssl'.");
                    Logger.DebugException(e);
                }
            }

            DatabaseManager.Commit();
            Stop();
        }
    }
}