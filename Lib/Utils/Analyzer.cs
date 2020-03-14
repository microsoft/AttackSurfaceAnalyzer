// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using Serilog;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;
using Utf8Json;

namespace AttackSurfaceAnalyzer.Utils
{
    public class Analyzer
    {
        private readonly Dictionary<RESULT_TYPE, List<PropertyInfo>> _Properties = new Dictionary<RESULT_TYPE, List<PropertyInfo>>()
        {
            {RESULT_TYPE.FILE , new List<PropertyInfo>(typeof(FileSystemObject).GetProperties()) },
            {RESULT_TYPE.CERTIFICATE, new List<PropertyInfo>(typeof(CertificateObject).GetProperties()) },
            {RESULT_TYPE.PORT, new List<PropertyInfo>(typeof(OpenPortObject).GetProperties()) },
            {RESULT_TYPE.REGISTRY, new List<PropertyInfo>(typeof(RegistryObject).GetProperties()) },
            {RESULT_TYPE.SERVICE, new List<PropertyInfo>(typeof(ServiceObject).GetProperties()) },
            {RESULT_TYPE.USER, new List<PropertyInfo>(typeof(UserAccountObject).GetProperties()) },
            {RESULT_TYPE.GROUP, new List<PropertyInfo>(typeof(UserAccountObject).GetProperties()) },
            {RESULT_TYPE.FIREWALL, new List<PropertyInfo>(typeof(FirewallObject).GetProperties()) },
            {RESULT_TYPE.COM, new List<PropertyInfo>(typeof(FirewallObject).GetProperties()) },
            {RESULT_TYPE.LOG, new List<PropertyInfo>(typeof(FirewallObject).GetProperties()) },

        };
        private readonly Dictionary<RESULT_TYPE, ANALYSIS_RESULT_TYPE> DEFAULT_RESULT_TYPE_MAP = new Dictionary<RESULT_TYPE, ANALYSIS_RESULT_TYPE>()
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
        };
        private readonly PLATFORM OsName;
        private RuleFile config;

        public Analyzer(PLATFORM platform, string filterLocation = "")
        {
            config = new RuleFile();

            if (string.IsNullOrEmpty(filterLocation))
            {
                LoadEmbeddedFilters();
            }
            else
            {
                LoadFilters(filterLocation);
            }

            OsName = platform;
        }

        public ANALYSIS_RESULT_TYPE Analyze(CompareResult compareResult)
        {
            if (compareResult == null) { return DEFAULT_RESULT_TYPE_MAP[RESULT_TYPE.UNKNOWN]; }
            var results = new List<ANALYSIS_RESULT_TYPE>();
            var curFilters = config.Rules.Where((rule) => (rule.ChangeTypes == null || rule.ChangeTypes.Contains(compareResult.ChangeType))
                                                     && (rule.Platforms == null || rule.Platforms.Contains(OsName))
                                                     && (rule.ResultType.Equals(compareResult.ResultType)))
                                                    .ToList();
            if (curFilters.Count > 0)
            {
                foreach (Rule rule in curFilters)
                {
                    results.Add(Apply(rule, compareResult));
                }

                return results.Max();
            }
            //If there are no filters for a result type
            return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Will gather exception information for analysis via telemetry.")]
        protected ANALYSIS_RESULT_TYPE Apply(Rule rule, CompareResult compareResult)
        {
            if (compareResult != null && rule != null)
            {
                var properties = _Properties[compareResult.ResultType];

                foreach (Clause clause in rule.Clauses)
                {
                    PropertyInfo property = properties.FirstOrDefault(iProp => iProp.Name.Equals(clause.Field));
                    if (property == null)
                    {
                        //Custom field logic will go here
                        return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];
                    }

                    try
                    {
                        var valsToCheck = new List<string>();
                        List<KeyValuePair<string, string>> dictToCheck = new List<KeyValuePair<string, string>>();

                        if (property != null)
                        {
                            if (compareResult.ChangeType == CHANGE_TYPE.CREATED || compareResult.ChangeType == CHANGE_TYPE.MODIFIED)
                            {
                                try
                                {
                                    if (GetValueByPropertyName(compareResult.Compare, property.Name) is List<string>)
                                    {
                                        foreach (var value in (List<string>)(GetValueByPropertyName(compareResult.Compare, property.Name) ?? new List<string>()))
                                        {
                                            valsToCheck.Add(value);
                                        }
                                    }
                                    else if (GetValueByPropertyName(compareResult.Compare, property.Name) is Dictionary<string, string>)
                                    {
                                        dictToCheck = ((Dictionary<string, string>)(GetValueByPropertyName(compareResult.Compare, property.Name) ?? new Dictionary<string,string>())).ToList();
                                    }
                                    else if (GetValueByPropertyName(compareResult.Compare, property.Name) is List<KeyValuePair<string, string>>)
                                    {
                                        dictToCheck = (List<KeyValuePair<string, string>>)(GetValueByPropertyName(compareResult.Compare, property.Name) ?? new List<KeyValuePair<string, string>>());
                                    }
                                    else
                                    {
                                        var val = GetValueByPropertyName(compareResult.Compare, property.Name)?.ToString();
                                        if (!string.IsNullOrEmpty(val))
                                        {
                                            valsToCheck.Add(val);
                                        }
                                    }
                                }
                                catch (Exception e)
                                {
                                    Log.Debug(e, "Error fetching Property {0} of Type {1}", property.Name, compareResult.ResultType);
                                    Log.Debug(Utf8Json.JsonSerializer.ToJsonString(compareResult));
                                    Dictionary<string, string> ExceptionEvent = new Dictionary<string, string>();
                                    ExceptionEvent.Add("Exception Type", e.GetType().ToString());
                                    AsaTelemetry.TrackEvent("ApplyCreatedModifiedException", ExceptionEvent);
                                }
                            }
                            if (compareResult.ChangeType == CHANGE_TYPE.DELETED || compareResult.ChangeType == CHANGE_TYPE.MODIFIED)
                            {
                                try
                                {
                                    if (GetValueByPropertyName(compareResult.Base, property.Name) is List<string>)
                                    {
                                        foreach (var value in (List<string>)(GetValueByPropertyName(compareResult.Base, property.Name) ?? new List<string>()))
                                        {
                                            valsToCheck.Add(value);
                                        }
                                    }
                                    else if (GetValueByPropertyName(compareResult.Base, property.Name) is Dictionary<string, string>)
                                    {
                                        dictToCheck = ((Dictionary<string, string>)(GetValueByPropertyName(compareResult.Base, property.Name) ?? new Dictionary<string, string>())).ToList();
                                    }
                                    else if (GetValueByPropertyName(compareResult.Base, property.Name) is List<KeyValuePair<string, string>>)
                                    {
                                        dictToCheck = (List<KeyValuePair<string, string>>)(GetValueByPropertyName(compareResult.Base, property.Name) ?? new List<KeyValuePair<string, string>>());
                                    }
                                    else
                                    {
                                        var val = GetValueByPropertyName(compareResult.Base, property.Name)?.ToString();
                                        if (!string.IsNullOrEmpty(val))
                                        {
                                            valsToCheck.Add(val);
                                        }
                                    }
                                }
                                catch (Exception e)
                                {
                                    Dictionary<string, string> ExceptionEvent = new Dictionary<string, string>();
                                    ExceptionEvent.Add("Exception Type", e.GetType().ToString());
                                    AsaTelemetry.TrackEvent("ApplyDeletedModifiedException", ExceptionEvent);
                                }
                            }
                        }

                        switch (clause.Operation)
                        {
                            case OPERATION.EQ:
                                if (clause.Data is List<string> EqualsData)
                                {
                                    if (EqualsData.Intersect(valsToCheck).Any())
                                    {
                                        break;
                                    }
                                }
                                return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];

                            case OPERATION.NEQ:
                                if (clause.Data is List<string> NotEqualsData)
                                {
                                    if (!NotEqualsData.Intersect(valsToCheck).Any())
                                    {
                                        break;
                                    }
                                }
                                return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];


                            // If *every* entry of the clause data is matched
                            case OPERATION.CONTAINS:
                                if (dictToCheck.Count > 0)
                                {
                                    if (clause.DictData is List<KeyValuePair<string, string>> ContainsData)
                                    {
                                        if (ContainsData.Where(y => dictToCheck.Where((x) => x.Key == y.Key && x.Value == y.Value).Any()).Count() == ContainsData.Count)
                                        {
                                            break;
                                        }
                                    }
                                }
                                else if (valsToCheck.Count > 0)
                                {
                                    if (clause.Data is List<string> ContainsDataList)
                                    {
                                        if (ContainsDataList.Intersect(valsToCheck).Count() == ContainsDataList.Count)
                                        {
                                            break;
                                        }
                                    }
                                }
                                return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];

                            // If *any* entry of the clause data is matched
                            case OPERATION.CONTAINS_ANY:
                                if (dictToCheck.Count > 0)
                                {
                                    if (clause.DictData is List<KeyValuePair<string, string>> ContainsData)
                                    {
                                        foreach (KeyValuePair<string, string> value in ContainsData)
                                        {
                                            if (dictToCheck.Where((x) => x.Key == value.Key && x.Value == value.Value).Any())
                                            {
                                                break;
                                            }
                                        }
                                    }
                                }
                                else if (valsToCheck.Count > 0)
                                {
                                    if (clause.Data is List<string> ContainsDataList)
                                    {
                                        if (clause.Data.Intersect(valsToCheck).Any())
                                        {
                                            break;
                                        }
                                    }
                                }
                                return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];

                            // If any of the clauses are not contained
                            case OPERATION.DOES_NOT_CONTAIN:
                                if (dictToCheck.Count > 0)
                                {
                                    if (clause.DictData is List<KeyValuePair<string, string>> ContainsData)
                                    {
                                        if (ContainsData.Where(y => dictToCheck.Where((x) => x.Key == y.Key && x.Value == y.Value).Any()).Any())
                                        {
                                            break;
                                        }
                                        return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];
                                    }
                                }
                                else if (valsToCheck.Count > 0)
                                {
                                    if (clause.Data is List<string> ContainsDataList)
                                    {
                                        if (ContainsDataList.Intersect(valsToCheck).Any())
                                        {
                                            break;
                                        }
                                        return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];
                                    }
                                }
                                break;

                            // If any of the data values are greater than the first provided data value
                            case OPERATION.GT:
                                if (valsToCheck.Where(val => (int.Parse(val, CultureInfo.InvariantCulture) > int.Parse(clause.Data?[0] ?? $"{int.MinValue}", CultureInfo.InvariantCulture))).Any()) { break; }
                                return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];

                            // If any of the data values are less than the first provided data value
                            case OPERATION.LT:
                                if (valsToCheck.Where(val => (int.Parse(val, CultureInfo.InvariantCulture) < int.Parse(clause.Data?[0] ?? $"{int.MaxValue}", CultureInfo.InvariantCulture))).Any()) { break; }
                                return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];

                            // If any of the regexes match any of the values
                            case OPERATION.REGEX:
                                if (clause.Data is List<string> RegexList)
                                {
                                    var regexList = RegexList.Select(x => new Regex(x));

                                    if (valsToCheck.Where(x => regexList.Where(y => y.IsMatch(x)).Any()).Any())
                                    {
                                        break;
                                    }
                                }
                                return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];

                            // Ignores provided data. Checks if the named property has changed.
                            case OPERATION.WAS_MODIFIED:
                                if ((valsToCheck.Count == 2) && (valsToCheck[0] == valsToCheck[1]))
                                {
                                    break;
                                }
                                return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];

                            // Ends with any of the provided data
                            case OPERATION.ENDS_WITH:
                                if (clause.Data is List<string> EndsWithData)
                                {
                                    if (valsToCheck.Where(x => EndsWithData.Where(y => x.EndsWith(y, StringComparison.CurrentCulture)).Any()).Any())
                                    {
                                        break;
                                    }
                                }
                                return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];

                            // Starts with any of the provided data
                            case OPERATION.STARTS_WITH:
                                if (clause.Data is List<string> StartsWithData)
                                {
                                    if (valsToCheck.Where(x => StartsWithData.Where(y => x.StartsWith(y, StringComparison.CurrentCulture)).Any()).Any())
                                    {
                                        break;
                                    }
                                }
                                return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];

                            default:
                                Log.Debug("Unimplemented operation {0}", clause.Operation);
                                return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];
                        }
                    }
                    catch (Exception e)
                    {
                        Log.Debug(e, $"Hit while parsing {JsonSerializer.Serialize(rule)} onto {JsonSerializer.Serialize(compareResult)}");
                        Dictionary<string, string> ExceptionEvent = new Dictionary<string, string>();
                        ExceptionEvent.Add("Exception Type", e.GetType().ToString());
                        AsaTelemetry.TrackEvent("ApplyOverallException", ExceptionEvent);
                        return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];
                    }
                }
                compareResult.Rules.Add(rule);
                return rule.Flag;
            }
            else
            {
                throw new NullReferenceException();
            }
        }

        private static object? GetValueByPropertyName(object? obj, string? propertyName) => obj?.GetType().GetProperty(propertyName ?? string.Empty)?.GetValue(obj);


        public void DumpFilters()
        {
            Log.Verbose("Filter dump:");
            Log.Verbose(JsonSerializer.ToJsonString(config));
        }

        public void LoadEmbeddedFilters()
        {
            try
            {
                var assembly = typeof(FileSystemObject).Assembly;
                var resourceName = "AttackSurfaceAnalyzer.analyses.json";
                using (Stream stream = assembly.GetManifestResourceStream(resourceName) ?? new MemoryStream())
                using (StreamReader reader = new StreamReader(stream))
                {
                    config = JsonSerializer.Deserialize<RuleFile>(reader.ReadToEnd());
                    Log.Information(Strings.Get("LoadedAnalyses"), "Embedded");
                }
                if (config == null)
                {
                    Log.Debug("No filters today.");
                    return;
                }
                DumpFilters();
            }
            catch (Exception e) when (
                e is ArgumentNullException
                || e is ArgumentException
                || e is FileLoadException
                || e is FileNotFoundException
                || e is BadImageFormatException
                || e is NotImplementedException)
            {

                config = new RuleFile();
                Log.Debug("Could not load filters {0} {1}", "Embedded", e.GetType().ToString());

                // This is interesting. We shouldn't hit exceptions when loading the embedded resource.
                Dictionary<string, string> ExceptionEvent = new Dictionary<string, string>();
                ExceptionEvent.Add("Exception Type", e.GetType().ToString());
                AsaTelemetry.TrackEvent("EmbeddedAnalysesFilterLoadException", ExceptionEvent);
            }
        }

        public void LoadFilters(string filterLoc = "")
        {
            if (!string.IsNullOrEmpty(filterLoc))
            {
                try
                {
                    using (StreamReader file = System.IO.File.OpenText(filterLoc))
                    {
                        config = JsonSerializer.Deserialize<RuleFile>(file.ReadToEnd());
                        Log.Information(Strings.Get("LoadedAnalyses"), filterLoc);
                    }
                    if (config == null)
                    {
                        Log.Debug("No filters this time.");
                        return;
                    }
                    DumpFilters();
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
                    config = new RuleFile();
                    //Let the user know we couldn't load their file
                    Log.Warning(Strings.Get("Err_MalformedFilterFile"), filterLoc);

                    return;
                }
            }
            
        }
    }
}


