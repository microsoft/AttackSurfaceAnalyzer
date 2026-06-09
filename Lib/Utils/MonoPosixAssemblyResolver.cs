// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using System;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.Loader;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Utils
{
    /// <summary>
    ///     Fallback resolver for the Mono.Posix.NETStandard assembly.
    ///
    ///     Mono.Posix.NETStandard 1.0.0 only ships its managed assembly under
    ///     runtimes/{rid}/lib/netstandard2.0/ and does not provide a win-arm64 runtime asset
    ///     (only win-x64, win-x86, linux-* and osx). Because the default host resolves that
    ///     assembly per-RID, on Windows ARM64 it cannot be found and a FileNotFoundException is
    ///     thrown whenever code that references Mono.Unix is JIT compiled (for example during
    ///     file system collection or monitoring).
    ///
    ///     The managed assembly is platform independent IL, so we resolve it from one of the
    ///     runtime folders that actually ships with the application. This only runs when the
    ///     default resolution fails, so it has no effect on platforms where the assembly already
    ///     resolves normally.
    /// </summary>
    internal static class MonoPosixAssemblyResolver
    {
        internal const string MonoPosixAssemblyName = "Mono.Posix.NETStandard";

        // RID-specific subfolders to probe, ordered by preference. win-arm64 is listed first so a
        // matching asset is preferred should one ever ship (the 1.0.0 package does not provide one);
        // the remaining RIDs all ship a managed Mono.Posix.NETStandard.dll that is identical IL.
        internal static readonly string[] CandidateRuntimeIdentifiers = new[]
        {
            "win-arm64",
            "win-x64",
            "win-x86",
            "linux-x64",
            "linux-arm64",
            "osx"
        };

        [ModuleInitializer]
        internal static void Initialize()
        {
            AssemblyLoadContext.Default.Resolving += ResolveMonoPosix;
        }

        internal static Assembly? ResolveMonoPosix(AssemblyLoadContext context, AssemblyName assemblyName)
        {
            var path = FindAssemblyPath(AppContext.BaseDirectory, assemblyName?.Name);
            if (path is null)
            {
                return null;
            }

            return context.LoadFromAssemblyPath(path);
        }

        /// <summary>
        ///     Returns the path to a shipped managed Mono.Posix.NETStandard.dll under the given base
        ///     directory, or null if the requested assembly is not Mono.Posix.NETStandard or no
        ///     shipped copy could be found.
        /// </summary>
        internal static string? FindAssemblyPath(string baseDirectory, string? assemblyName)
        {
            if (string.IsNullOrEmpty(baseDirectory) || !string.Equals(assemblyName, MonoPosixAssemblyName, StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            foreach (var rid in CandidateRuntimeIdentifiers)
            {
                var candidate = Path.Combine(baseDirectory, "runtimes", rid, "lib", "netstandard2.0", $"{MonoPosixAssemblyName}.dll");
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }

            return null;
        }
    }
}
