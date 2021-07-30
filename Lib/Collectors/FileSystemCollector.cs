// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Microsoft.CodeAnalysis;
using Microsoft.CST.RecursiveExtractor;
using Mono.Unix;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Security.Permissions;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    ///     Collects Filesystem Data from the local file system.
    /// </summary>
    public class FileSystemCollector : BaseCollector
    {
        public FileSystemCollector(CollectorOptions? opts = null, Action<CollectObject>? changeHandler = null) : base(opts, changeHandler)
        {
            Roots.AddRange(opts?.SelectedDirectories ?? new List<string>());

            if (!Roots.Any())
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    foreach (var driveInfo in DriveInfo.GetDrives())
                    {
                        if (driveInfo.IsReady && driveInfo.DriveType == DriveType.Fixed)
                        {
                            Roots.Add(driveInfo.Name);
                        }
                    }
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    foreach (var directory in Directory.EnumerateDirectories("/"))
                    {
                        if (!directory.Equals("/proc") && !directory.Equals("/sys"))
                        {
                            Roots.Add(directory);
                        }
                        else
                        {
                            Log.Debug("Default settings skip directories /proc and /sys because they tend to have non-files which stall the collector.");
                        }
                    }
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    Roots.Add("/");
                }
            }
        }

        public static ConcurrentDictionary<string, uint> ClusterSizes { get; set; } = new ConcurrentDictionary<string, uint>();
        public List<string> Roots { get; } = new List<string>();
        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        /// <summary>
        ///     Converts a FileSystemInfo into a FileSystemObject by reading in data about the file
        /// </summary>
        /// <param name="fileInfo"> A reference to a file on disk. </param>
        /// <param name="downloadCloud">
        ///     If the file is hosted in the cloud, the user has the option to include cloud files or not.
        /// </param>
        /// <param name="includeContentHash"> If we should generate a hash of the file. </param>
        /// <returns> </returns>
        public FileSystemObject FilePathToFileSystemObject(string path)
        {
            FileSystemObject obj = new FileSystemObject(path);

            // Get Owner/Group
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                try
                {
                    var fileSecurity = new FileSecurity(path, AccessControlSections.Owner);
                    IdentityReference? oid = fileSecurity.GetOwner(typeof(SecurityIdentifier));
                    obj.Owner = AsaHelpers.SidToName(oid);
                }
                catch (Exception e)
                {
                    Log.Verbose("Failed to get owner for {0} ({1}:{2})", path, e.GetType(), e.Message);
                }
                try
                {
                    var fileSecurity = new FileSecurity(path, AccessControlSections.Group);
                    IdentityReference? gid = fileSecurity.GetGroup(typeof(SecurityIdentifier));
                    obj.Group = AsaHelpers.SidToName(gid);
                }
                catch (Exception e)
                {
                    Log.Verbose("Failed to get group for {0} ({1}:{2})", path, e.GetType(), e.Message);
                }
                try
                {
                    var fileSecurity = new FileSecurity(path, AccessControlSections.Access);
                    var rules = fileSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier));
                    obj.Permissions = new Dictionary<string, string>();
                    foreach (FileSystemAccessRule? rule in rules)
                    {
                        if (rule != null)
                        {
                            string name = AsaHelpers.SidToName(rule.IdentityReference);

                            foreach (var permission in rule.FileSystemRights.ToString().Split(','))
                            {
                                if (obj.Permissions.ContainsKey(name))
                                {
                                    obj.Permissions[name] = $"{obj.Permissions[name]},{permission}";
                                }
                                else
                                {
                                    obj.Permissions.Add(name, permission);
                                }
                            }
                        }
                    }
                }
                catch (Exception e)
                {
                    Log.Verbose("Failed to get FileSecurity for {0} ({1}:{2})", path, e.GetType(), e.Message);
                }
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                try
                {
                    var file = new UnixSymbolicLinkInfo(path);
                    obj.Owner = file.OwnerUser.UserName;
                    obj.Group = file.OwnerGroup.GroupName;
                    obj.SetGid = file.IsSetGroup;
                    obj.SetUid = file.IsSetUser;

                    obj.Permissions = new Dictionary<string, string>();
                    if (file.FileAccessPermissions.ToString().Equals("AllPermissions", StringComparison.InvariantCulture))
                    {
                        obj.Permissions.Add("User", "Read,Write,Execute");
                        obj.Permissions.Add("Group", "Read,Write,Execute");
                        obj.Permissions.Add("Other", "Read,Write,Execute");
                    }
                    else
                    {
                        var keys = new List<string>() { "User", "Group", "Other" };
                        var splits = file.FileAccessPermissions.ToString().Split(',').Select(x => x.Trim());
                        foreach (var key in keys)
                        {
                            foreach (var permission in splits.Where((x) => x.StartsWith(key, StringComparison.InvariantCulture)))
                            {
                                if (permission.Contains("ReadWriteExecute", StringComparison.InvariantCulture))
                                {
                                    obj.Permissions.Add(key, "Read,Write,Execute");
                                }
                                else
                                {
                                    if (obj.Permissions.ContainsKey(key))
                                    {
                                        obj.Permissions[key] = $"{obj.Permissions[key]},{permission.Trim().Substring(key.Length)}";
                                    }
                                    else
                                    {
                                        obj.Permissions.Add(key, permission.Trim().Substring(key.Length));
                                    }
                                }
                            }
                        }
                    }
                }
                catch (Exception e) when (
                    e is ArgumentNullException
                    || e is ArgumentException
                    || e is InvalidOperationException)
                {
                    Log.Verbose("Failed to get permissions for {0} ({1}:{2})", path, e.GetType(), e.Message);
                }
            }

            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    if (Directory.Exists(path))
                    {
                        var fileInfo = new DirectoryInfo(path);
                        if (fileInfo.Attributes.HasFlag(FileAttributes.ReparsePoint))
                        {
                            obj.IsLink = true;
                            obj.Target = NativeMethods.GetFinalPathName(path);
                        }
                        else
                        {
                            obj.IsDirectory = true;
                        }
                    }
                    else
                    {
                        var fileInfo = new FileInfo(path);
                        obj.Size = fileInfo.Length;
                        obj.SizeOnDisk = WindowsSizeOnDisk(fileInfo);

                        // This check is to try to prevent reading of cloud based files (like a dropbox
                        // folder) and subsequently causing a download, unless the user specifically requests
                        // it with DownloadCloud.
                        if (opts.DownloadCloud || obj.SizeOnDisk > 0 || WindowsFileSystemUtils.IsLocal(obj.Path))
                        {
                            obj.LastModified = File.GetLastWriteTimeUtc(path);
                            obj.Created = File.GetCreationTimeUtc(path);

                            if (opts.GatherHashes == true)
                            {
                                obj.ContentHash = FileSystemUtils.GetFileHash(fileInfo);
                            }

                            var exeType = FileSystemUtils.GetExecutableType(path);

                            if (exeType != EXECUTABLE_TYPE.NONE && exeType != EXECUTABLE_TYPE.UNKNOWN)
                            {
                                obj.IsExecutable = true;
                            }

                            if (exeType == EXECUTABLE_TYPE.WINDOWS)
                            {
                                obj.SignatureStatus = WindowsFileSystemUtils.GetSignatureStatus(path);
                                obj.Characteristics = WindowsFileSystemUtils.GetDllCharacteristics(path);
                            }
                            else if (exeType == EXECUTABLE_TYPE.MACOS)
                            {
                                obj.MacSignatureStatus = FileSystemUtils.GetMacSignature(path);
                            }
                        }
                    }
                }
                else
                {
                    UnixSymbolicLinkInfo i = new UnixSymbolicLinkInfo(path);
                    obj.FileType = i.FileType.ToString();
                    obj.Size = i.Length;
                    obj.IsDirectory = false;
                    switch (i.FileType)
                    {
                        case FileTypes.SymbolicLink:
                            obj.IsLink = true;
                            obj.Target = i.ContentsPath;
                            break;

                        case FileTypes.Fifo:
                        case FileTypes.Socket:
                        case FileTypes.BlockDevice:
                        case FileTypes.CharacterDevice:
                        case FileTypes.Directory:
                            obj.IsDirectory = true;
                            if (path?.EndsWith(".app", StringComparison.InvariantCultureIgnoreCase) ?? false)
                            {
                                obj.MacSignatureStatus = FileSystemUtils.GetMacSignature(path);
                            }
                            break;

                        case FileTypes.RegularFile:
                            var fileInfo = new FileInfo(path);
                            obj.SizeOnDisk = i.BlocksAllocated * i.BlockSize;
                            if (opts.DownloadCloud || obj.SizeOnDisk > 0)
                            {
                                obj.LastModified = File.GetLastWriteTimeUtc(path);
                                obj.Created = File.GetCreationTimeUtc(path);

                                if (opts.GatherHashes)
                                {
                                    obj.ContentHash = FileSystemUtils.GetFileHash(path);
                                }

                                var exeType = FileSystemUtils.GetExecutableType(path);

                                if (exeType != EXECUTABLE_TYPE.NONE && exeType != EXECUTABLE_TYPE.UNKNOWN)
                                {
                                    obj.IsExecutable = true;
                                }

                                if (exeType == EXECUTABLE_TYPE.WINDOWS)
                                {
                                    obj.SignatureStatus = WindowsFileSystemUtils.GetSignatureStatus(path);
                                    obj.Characteristics = WindowsFileSystemUtils.GetDllCharacteristics(path);
                                }
                                else if (exeType == EXECUTABLE_TYPE.MACOS)
                                {
                                    obj.MacSignatureStatus = FileSystemUtils.GetMacSignature(path);
                                }
                            }
                            break;
                    }
                }
            }
            catch (Exception e) when (
                e is ArgumentNullException ||
                e is SecurityException ||
                e is ArgumentException ||
                e is UnauthorizedAccessException ||
                e is PathTooLongException ||
                e is NotSupportedException ||
                e is InvalidOperationException ||
                e is FileNotFoundException ||
                e is Win32Exception ||
                e is IOException)
            {
                Log.Verbose("Failed to create FileInfo from File at {0} ({1}:{2})", path, e.GetType(), e.Message);
            }
            catch (Exception e)
            {
                Log.Debug("Should be caught in DirectoryWalker {0} {1}", e.GetType().ToString(), path);
            }

            if (path is not null)
            {
                try
                {
                    obj.LastModified = File.GetLastWriteTimeUtc(path);
                    obj.Created = File.GetCreationTimeUtc(path);
                }
                catch (Exception e)
                {
                    Log.Verbose("Failed to get last modified for {0} ({1}:{2})", path, e.GetType(), e.Message);
                }
            }

            return obj;
        }

        internal override void ExecuteInternal(CancellationToken cancellationToken)
        {
            foreach (var Root in Roots.Where(x => !opts.SkipDirectories.Any(y => x.StartsWith(y))))
            {
                Log.Information("{0} root {1}", Strings.Get("Scanning"), Root);
                var directories = Directory.EnumerateDirectories(Root, "*", new System.IO.EnumerationOptions()
                {
                    ReturnSpecialDirectories = false,
                    IgnoreInaccessible = true,
                    RecurseSubdirectories = true
                }).Where(x => !opts.SkipDirectories.Any(y => x.StartsWith(y)));

                // Process files in the root
                TryIterateOnDirectory(Root);

                if (!opts.SingleThread == true)
                {
                    ParallelOptions po = new ParallelOptions() { CancellationToken = cancellationToken };
                    Parallel.ForEach(directories, po, filePath =>
                    {
                        TryIterateOnDirectory(filePath);
                    });
                }
                else
                {
                    foreach (var filePath in directories)
                    {
                        if (cancellationToken.IsCancellationRequested)
                        {
                            break;
                        }
                        TryIterateOnDirectory(filePath);
                    }
                }
            }
        }

        private static long WindowsSizeOnDisk(FileInfo path)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                try
                {
                    uint clusterSize = 0;
                    var root = path.Directory?.Root.FullName;
                    if (root is null)
                    {
                        throw new ArgumentNullException(nameof(path.Directory));
                    }
                    if (!ClusterSizes.ContainsKey(root))
                    {
                        NativeMethods.GetDiskFreeSpace(root, out uint lpSectorsPerCluster, out uint lpBytesPerSector, out _, out _);
                        ClusterSizes[root] = lpSectorsPerCluster * lpBytesPerSector;
                    }
                    clusterSize = ClusterSizes[root];

                    if (clusterSize > 0)
                    {
                        uint lowSize = NativeMethods.GetCompressedFileSizeW(path.FullName, out uint highSize);
                        long size = (long)highSize << 32 | lowSize;
                        return ((size + clusterSize - 1) / clusterSize) * clusterSize;
                    }
                }
                catch (Exception e)
                {
                    Log.Debug("Failed to GetDiskFreeSpace for {0} ({1}:{2})", path.FullName, e.GetType(), e.Message);
                }
            }
            return -1;
        }

        private FileSystemObject FileEntryToFileSystemObject(FileEntry fileEntry)
        {
            var fso = new FileSystemObject(Path: fileEntry.FullPath)
            {
                Size = fileEntry.Content.Length
            };

            if (opts.GatherHashes == true)
            {
                fso.ContentHash = CryptoHelpers.CreateHash(fileEntry.Content);
            }

            var exeType = FileSystemUtils.GetExecutableType(fileEntry.FullPath, fileEntry.Content);

            if (exeType != EXECUTABLE_TYPE.NONE && exeType != EXECUTABLE_TYPE.UNKNOWN)
            {
                fso.IsExecutable = true;
            }

            if (exeType == EXECUTABLE_TYPE.WINDOWS)
            {
                fso.SignatureStatus = WindowsFileSystemUtils.GetSignatureStatus(fileEntry.FullPath, fileEntry.Content);
                fso.Characteristics = WindowsFileSystemUtils.GetDllCharacteristics(fileEntry.FullPath, fileEntry.Content);
            }

            return fso;
        }

        private void ParseFile(string path)
        {
            Log.Verbose("Started parsing {0}", path);
            FileSystemObject obj = FilePathToFileSystemObject(path);
            if (obj != null)
            {
                HandleChange(obj);

                // If we know how to handle this as an archive, and crawling archives is enabled
                if (opts.CrawlArchives && MiniMagic.DetectFileType(path) != ArchiveFileType.UNKNOWN)
                {
                    var opts = new ExtractorOptions() { ExtractSelfOnFail = false };
                    Extractor extractor = new Extractor();
                    foreach (var fso in extractor.Extract(path, opts).Select(fileEntry => FileEntryToFileSystemObject(fileEntry)))
                    {
                        HandleChange(fso);
                    }
                }

                // TODO: Also try parse .DER as a key
                if (path.EndsWith(".cer", StringComparison.CurrentCulture) ||
                    path.EndsWith(".der", StringComparison.CurrentCulture) ||
                    path.EndsWith(".p7b", StringComparison.CurrentCulture) ||
                    path.EndsWith(".pfx", StringComparison.CurrentCulture))
                {
                    try
                    {
                        using var certificate = new X509Certificate2(path);

                        var certObj = new CertificateObject(
                            StoreLocation: StoreLocation.LocalMachine.ToString(),
                            StoreName: StoreName.Root.ToString(),
                            Certificate: new SerializableCertificate(certificate));

                        HandleChange(certObj);
                    }
                    catch (Exception e)
                    {
                        Log.Verbose("Could not parse certificate from file: {0} ({1}:{2})", path, e.GetType(), e.Message);
                    }
                }
            }
            Log.Verbose("Finished parsing {0}", path);
        }

        private void TryIterateOnDirectory(string path)
        {
            try
            {
                Log.Verbose("Started parsing {0}", path);

                var files = Directory.EnumerateFiles(path, "*", new System.IO.EnumerationOptions()
                {
                    IgnoreInaccessible = true
                });

                if (opts.SingleThread)
                {
                    foreach (var file in files)
                    {
                        ParseFile(file);
                    }
                }
                else
                {
                    Parallel.ForEach(files, file => ParseFile(file));
                }
            }
            catch (Exception e)
            {
                Log.Verbose("Error parsing Directory {0} ({1}:{2})", path, e.GetType(), e.Message);
            }
            Log.Verbose("Finished parsing {0}", path);
        }
    }
}