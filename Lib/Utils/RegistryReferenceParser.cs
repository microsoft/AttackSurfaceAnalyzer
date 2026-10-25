// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Utils
{
    /// <summary>
    ///     Cracks file paths and CLSIDs out of raw registry value data and normalizes registry-stored binary
    ///     references into paths on disk.
    /// </summary>
    /// <remarks>
    ///     Extraction runs for every value of every key of every hive in both registry views, so it is pure
    ///     string manipulation over compiled expressions and never touches the disk. Cheap substring
    ///     pre-filters keep the regexes from running at all for the overwhelming majority of values
    ///     (base64-encoded REG_BINARY blobs, numbers, and plain words contain none of the trigger
    ///     characters).
    /// </remarks>
    public static class RegistryReferenceParser
    {
        /// <summary>
        ///     Values longer than this are not scanned. Registry values can hold megabytes of binary data and
        ///     no load point reference lives past this bound.
        /// </summary>
        public const int MaxScannedValueLength = 8192;

        /// <summary>
        ///     The most references of each kind taken from a single value.
        /// </summary>
        public const int MaxReferencesPerValue = 32;

        /// <summary>
        ///     Extracts CLSID-shaped GUIDs from raw registry value data, normalized to braced uppercase form.
        /// </summary>
        public static IEnumerable<string> ExtractClsids(string? value)
        {
            if (value is null || value.Length == 0 || value.Length > MaxScannedValueLength)
            {
                return Array.Empty<string>();
            }

            // Every GUID shape we accept contains hyphens; bail before touching the regex engine if there
            // are none.
            if (value.IndexOf('-') < 0)
            {
                return Array.Empty<string>();
            }

            List<string> results = new();
            HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);

            try
            {
                for (var match = ClsidRegex.Match(value); match.Success; match = match.NextMatch())
                {
                    var clsid = $"{{{match.Groups["guid"].Value.ToUpperInvariant()}}}";
                    if (seen.Add(clsid))
                    {
                        results.Add(clsid);
                        if (results.Count >= MaxReferencesPerValue)
                        {
                            break;
                        }
                    }
                }
            }
            catch (RegexMatchTimeoutException)
            {
                return results;
            }

            return results;
        }

        /// <summary>
        ///     Extracts rooted file paths (drive-qualified, UNC, or environment-variable rooted) from raw
        ///     registry value data. Results are environment-expanded and normalized.
        /// </summary>
        public static IEnumerable<string> ExtractPaths(string? value)
        {
            if (value is null || value.Length == 0 || value.Length > MaxScannedValueLength)
            {
                return Array.Empty<string>();
            }

            // Every path shape we accept is rooted by a drive letter, a UNC prefix, or an environment
            // variable, so it must contain a backslash or a percent sign.
            if (value.IndexOf('\\') < 0 && value.IndexOf('%') < 0)
            {
                return Array.Empty<string>();
            }

            List<string> results = new();
            HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);

            try
            {
                for (var match = PathRegex.Match(value); match.Success; match = match.NextMatch())
                {
                    var path = NormalizePath(match.Value);
                    if (path is not null && seen.Add(path))
                    {
                        results.Add(path);
                        if (results.Count >= MaxReferencesPerValue)
                        {
                            break;
                        }
                    }
                }
            }
            catch (RegexMatchTimeoutException)
            {
                return results;
            }

            return results;
        }

        /// <summary>
        ///     Pulls the executable out of a command line, as stored in LocalServer32 or a service ImagePath.
        /// </summary>
        /// <remarks>
        ///     An unquoted path containing spaces is genuinely ambiguous to the loader as well, so the first
        ///     token ending in .exe is preferred before falling back to splitting on whitespace.
        /// </remarks>
        public static string? ExtractExecutablePath(string? commandLine)
        {
            if (string.IsNullOrWhiteSpace(commandLine))
            {
                return null;
            }

            var value = commandLine.Trim();

            if (value[0] == '"')
            {
                var end = value.IndexOf('"', 1);
                return NormalizePath(end > 1 ? value.Substring(1, end - 1) : value.Trim('"'));
            }

            try
            {
                var match = ExecutableExtensionRegex.Match(value);
                if (match.Success)
                {
                    return NormalizePath(value.Substring(0, match.Index + match.Length));
                }
            }
            catch (RegexMatchTimeoutException)
            {
                // Fall through to whitespace splitting.
            }

            var space = value.IndexOf(' ');
            return NormalizePath(space > 0 ? value.Substring(0, space) : value);
        }

        /// <summary>
        ///     Normalizes a registry-stored binary reference into a path on disk: strips surrounding quotes,
        ///     expands environment variables, resolves native object-manager prefixes, and qualifies bare
        ///     binary names against System32 the way the loader would.
        /// </summary>
        public static string? NormalizePath(string? raw)
        {
            if (string.IsNullOrWhiteSpace(raw))
            {
                return null;
            }

            var path = raw.Trim();

            // Quoted paths break permission lookups downstream.
            if (path.Length > 1 && path[0] == '"' && path[path.Length - 1] == '"')
            {
                path = path.Substring(1, path.Length - 2).Trim();
            }

            if (path.Length == 0)
            {
                return null;
            }

            try
            {
                path = Environment.ExpandEnvironmentVariables(path);
            }
            catch (Exception)
            {
                // A malformed value is left as-is rather than dropped.
            }

            if (path.StartsWith(@"\??\", StringComparison.Ordinal))
            {
                path = path.Substring(4);
            }
            else if (path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            {
                path = Path.Combine(SystemRoot, path.Substring(@"\SystemRoot\".Length));
            }

            path = path.Trim();

            if (path.Length == 0)
            {
                return null;
            }

            // An unqualified binary name is resolved by the loader out of System32.
            if (path.IndexOf('\\') < 0 && path.IndexOf('/') < 0 && path.IndexOf('%') < 0)
            {
                path = Path.Combine(Environment.SystemDirectory, path);
            }

            return path;
        }

        private static string SystemRoot
        {
            get
            {
                var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                return string.IsNullOrEmpty(windows) ? @"C:\Windows" : windows;
            }
        }

        private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(100);

        private static readonly Regex ClsidRegex = new(
            @"\{?(?<guid>[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}?",
            RegexOptions.Compiled | RegexOptions.CultureInvariant,
            RegexTimeout);

        private static readonly Regex ExecutableExtensionRegex = new(
            @"\.exe\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase,
            RegexTimeout);

        /// <summary>
        ///     A drive-letter, UNC, or environment-variable rooted path running lazily up to a file
        ///     extension. The trailing lookahead forces the extension to end at a natural delimiter so that
        ///     "C:\a\b.check" is not truncated to "C:\a\b.c".
        /// </summary>
        private static readonly Regex PathRegex = new(
            @"(?:[A-Za-z]:\\|\\\\|%[A-Za-z_][A-Za-z0-9_()]{0,63}%\\)[^""<>|\r\n\t]*?\.[A-Za-z0-9]{1,8}(?![^\s""',;)\]])",
            RegexOptions.Compiled | RegexOptions.CultureInvariant,
            RegexTimeout);
    }
}
