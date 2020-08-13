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
        public RuleFile(Dictionary<RESULT_TYPE, ANALYSIS_RESULT_TYPE>? DefaultLevels = null, List<AsaRule>? Rules = null)
        {
            this.DefaultLevels = DefaultLevels ?? this.DefaultLevels;
            this.Rules = Rules ?? new List<AsaRule>();
        }

        public RuleFile()
        {
        }

        public string? Source { get; set; } // An Identifier for the source of the rules

        public IEnumerable<AsaRule> Rules { get; set; } = new List<AsaRule>();

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

        public static RuleFile FromStream(Stream? stream)
        {
            if (stream is null)
                throw new NullReferenceException(nameof(stream));
            try
            {
                using (StreamReader file = new StreamReader(stream))
                {
                    var config = JsonConvert.DeserializeObject<RuleFile>(file.ReadToEnd());
                    if (config.Source is null)
                        config.Source = "Stream";
                    Log.Information(Strings.Get("LoadedAnalyses"), config.Source);
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

        public static RuleFile FromFile(string? filterLoc = "")
        {
            if (!string.IsNullOrEmpty(filterLoc))
            {
                try
                {
                    using (StreamReader file = System.IO.File.OpenText(filterLoc))
                    {
                        var config = JsonConvert.DeserializeObject<RuleFile>(file.ReadToEnd());
                        if (config.Source is null)
                            config.Source = filterLoc;
                        Log.Information(Strings.Get("LoadedAnalyses"), config.Source);
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

        public static RuleFile LoadEmbeddedFilters()
        {
            try
            {
                var assembly = typeof(FileSystemObject).Assembly;
                var resourceName = "AttackSurfaceAnalyzer.analyses.json";
                using Stream stream = assembly.GetManifestResourceStream(resourceName) ?? throw new NullReferenceException($"assembly.GetManifestResourceStream couldn't load {resourceName}");
                var file = FromStream(stream);
                file.Source = "Embedded Rules";
                Log.Information(Strings.Get("LoadedAnalyses"), "Embedded");
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

                // This is interesting. We shouldn't hit exceptions when loading the embedded resource.
                Dictionary<string, string> ExceptionEvent = new Dictionary<string, string>();
                ExceptionEvent.Add("Exception Type", e.GetType().ToString());
                AsaTelemetry.TrackEvent("EmbeddedAnalysesFilterLoadException", ExceptionEvent);
            }
            return new RuleFile();
        }

        public void DumpFilters()
        {
            Log.Verbose("Filter dump:");
            Log.Verbose(JsonConvert.SerializeObject(this));
        }

        public List<Rule> GetRules()
        {
            return Rules.Select(x => (Rule)x).ToList(); ;
        }

        public List<Rule> GetRulesForPlatform(PLATFORM platform)
        {
            return (List<Rule>)Rules.Where(x => x.Platforms.Contains(platform) || !x.Platforms.Any());
        }
    }
}