// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Microsoft.CST.OAT;
using Newtonsoft.Json;
using Serilog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    public class RuleFile
    {
        /// <summary>
        /// Create a RuleFile with provided DefaultLevels, Rules and Source name.
        /// </summary>
        /// <param name="DefaultLevels"></param>
        /// <param name="Rules"></param>
        /// <param name="Source"></param>
        [JsonConstructor]
        public RuleFile(Dictionary<RESULT_TYPE, ANALYSIS_RESULT_TYPE>? DefaultLevels = null, IEnumerable<AsaRule>? Rules = null, string? Source = null)
        {
            this.DefaultLevels = DefaultLevels ?? this.DefaultLevels;
            this.Rules = Rules ?? new List<AsaRule>();
            this.Source = Source;
        }

        /// <summary>
        /// Create a RuleFile with the default Default Levels and null Source name.
        /// </summary>
        /// <param name="Rules"></param>
        public RuleFile(IEnumerable<AsaRule>? Rules = null) : this(null, Rules, null)
        {
        }

        /// <summary>
        /// Create an empty RuleFile.
        /// </summary>
        public RuleFile()
        {
        }

        /// <summary>
        /// An Identifier for the source of the Rules
        /// </summary>
        public string? Source { get; set; }

        /// <summary>
        /// The List of Rules
        /// </summary>
        public IEnumerable<AsaRule> Rules { get; set; } = new List<AsaRule>();

        /// <summary>
        /// The Default Levels to apply to objects if there is no corresponding rule.
        /// </summary>
        public Dictionary<RESULT_TYPE, ANALYSIS_RESULT_TYPE> DefaultLevels { get; set; } = new Dictionary<RESULT_TYPE, ANALYSIS_RESULT_TYPE>()
        {
            { RESULT_TYPE.CERTIFICATE, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.FILE, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.PORT, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.REGISTRY, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.SERVICE, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.USER, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.UNKNOWN, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.GROUP, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.COM, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.LOG, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.KEY, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.TPM, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.PROCESS, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.DRIVER, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.FILEMONITOR, ANALYSIS_RESULT_TYPE.INFORMATION }
        };

        /// <summary>
        /// Generate a RuleFile from a given stream containing a serialized RuleFile.
        /// </summary>
        /// <param name="stream">The Stream to Deserialize</param>
        /// <param name="streamName">The Source Name to set in the RuleFile</param>
        /// <returns></returns>
        public static RuleFile FromStream(Stream? stream, string? streamName)
        {
            if (stream is null)
                throw new NullReferenceException(nameof(stream));
            try
            {
                using (StreamReader file = new StreamReader(stream))
                {
                    var config = JsonConvert.DeserializeObject<RuleFile>(file.ReadToEnd());
                    config.Source = streamName ?? (config.Source ?? "Stream");
                    return config;
                }
            }
            catch (Exception e) when (
                e is UnauthorizedAccessException
                || e is ArgumentException
                || e is ArgumentNullException
                || e is PathTooLongException
                || e is DirectoryNotFoundException
                || e is FileNotFoundException
                || e is NotSupportedException)
            {
                //Let the user know we couldn't load their file
                Log.Warning(Strings.Get("Err_MalformedFilterFile"), "Stream");
            }
            return new RuleFile();
        }

        /// <summary>
        /// Get the Hash of the RuleFile
        /// </summary>
        /// <returns></returns>
        public string GetHash() => CryptoHelpers.CreateHash(JsonConvert.SerializeObject(this));

        /// <summary>
        /// Load rules from a serialized RuleFile on disk.
        /// </summary>
        /// <param name="filterLoc"></param>
        /// <returns></returns>
        public static RuleFile FromFile(string? filterLoc = "")
        {
            if (!string.IsNullOrEmpty(filterLoc))
            {
                try
                {
                    using (StreamReader file = System.IO.File.OpenText(filterLoc))
                    {
                        var config = JsonConvert.DeserializeObject<RuleFile>(file.ReadToEnd());
                        config.Source = filterLoc;
                        return config;
                    }
                }
                catch (Exception e) when (
                    e is UnauthorizedAccessException
                    || e is ArgumentException
                    || e is ArgumentNullException
                    || e is PathTooLongException
                    || e is DirectoryNotFoundException
                    || e is FileNotFoundException
                    || e is NotSupportedException)
                {
                    //Let the user know we couldn't load their file
                    Log.Warning(Strings.Get("Err_MalformedFilterFile"), filterLoc);
                }
            }
            return new RuleFile();
        }

        /// <summary>
        /// Load the default AttackSurfaceAnalyzer Rules embedded in the binary.
        /// </summary>
        /// <returns></returns>
        public static RuleFile LoadEmbeddedFilters()
        {
            try
            {
                var assembly = typeof(FileSystemObject).Assembly;
                var resourceName = "AttackSurfaceAnalyzer.analyses.json";
                using Stream stream = assembly.GetManifestResourceStream(resourceName) ?? throw new NullReferenceException($"assembly.GetManifestResourceStream couldn't load {resourceName}");
                var file = FromStream(stream, "Embedded Rules");
                return file;
            }
            catch (Exception e) when (
                e is ArgumentNullException
                || e is ArgumentException
                || e is FileLoadException
                || e is FileNotFoundException
                || e is BadImageFormatException
                || e is NotImplementedException
                || e is NullReferenceException)
            {
                Log.Debug("Could not load filters {0} {1}", "Embedded", e.GetType().ToString());
            }
            return new RuleFile();
        }

        /// <summary>
        /// Print a serialization of the filters to the verbose console.
        /// </summary>
        public void DumpFilters()
        {
            Log.Verbose("Filter dump:");
            Log.Verbose(JsonConvert.SerializeObject(this));
        }
    }
}