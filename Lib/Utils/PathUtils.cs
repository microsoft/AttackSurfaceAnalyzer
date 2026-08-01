// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Serilog;
using System;
using System.IO;
using System.Runtime.InteropServices;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Utils
{
    /// <summary>
    ///     Decides whether a path names something on this machine.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         Paths recovered from the registry are not necessarily local, and whoever can write the value
    ///         chooses which machine they name. Resolving one is not a passive read: it opens a session to
    ///         that host and authenticates as the account running the collection, which for most of these
    ///         collectors is an administrator, and then reads content that host controls. That is a surprise
    ///         for anyone who asked only for a local snapshot.
    ///     </para>
    ///     <para>
    ///         Collectors therefore ask this before they touch a path, in the same way the file system
    ///         collector asks whether a file is a cloud placeholder before hydrating it.
    ///     </para>
    /// </remarks>
    public static class PathUtils
    {
        /// <summary>
        ///     Whether resolving this path would reach off the machine, through either a UNC path or a drive
        ///     letter mapped to a network share. Answered from the path itself and the local mount table, so
        ///     asking never touches the network.
        /// </summary>
        public static bool IsNetworkPath(string? path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return false;
            }

            var candidate = path!.Trim();

            // \\?\ and \\.\ turn off path parsing; what follows the prefix is what is named. \\?\UNC\server\share
            // is the extended-length spelling of \\server\share.
            if (candidate.StartsWith(@"\\?\", StringComparison.Ordinal)
                || candidate.StartsWith(@"\\.\", StringComparison.Ordinal))
            {
                candidate = candidate.Substring(4);

                if (candidate.StartsWith(@"UNC\", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            else if (candidate.StartsWith(@"\\", StringComparison.Ordinal))
            {
                return true;
            }

            return IsNetworkDrive(candidate);
        }

        /// <summary>
        ///     Whether a drive-letter rooted path resolves through a mapped network drive. A UNC path reached
        ///     this way is indistinguishable from a local one by inspection, so the drive itself is asked.
        /// </summary>
        private static bool IsNetworkDrive(string path)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || path.Length < 2 || path[1] != ':')
            {
                return false;
            }

            try
            {
                return new DriveInfo(path.Substring(0, 1)).DriveType == DriveType.Network;
            }
            catch (Exception e)
            {
                // An unusable drive letter is not evidence that the path is remote. The caller's own error
                // handling deals with it when the path fails to resolve.
                Log.Verbose("Failed to determine the drive type of {0} ({1}:{2})", path, e.GetType(), e.Message);
                return false;
            }
        }
    }
}
