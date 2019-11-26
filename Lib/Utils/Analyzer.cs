// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using Serilog;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;

namespace AttackSurfaceAnalyzer.Utils
{
    public class Analyzer
    {
        Dictionary<RESULT_TYPE, List<PropertyInfo>> _Properties = new Dictionary<RESULT_TYPE, List<PropertyInfo>>()
        {
            {RESULT_TYPE.FILE , new List<PropertyInfo>(new FileSystemObject().GetType().GetProperties()) },
            {RESULT_TYPE.CERTIFICATE, new List<PropertyInfo>(new CertificateObject().GetType().GetProperties()) },
            {RESULT_TYPE.PORT, new List<PropertyInfo>(new OpenPortObject().GetType().GetProperties()) },
            {RESULT_TYPE.REGISTRY, new List<PropertyInfo>(new RegistryObject().GetType().GetProperties()) },
            {RESULT_TYPE.SERVICE, new List<PropertyInfo>(new ServiceObject().GetType().GetProperties()) },
            {RESULT_TYPE.USER, new List<PropertyInfo>(new UserAccountObject().GetType().GetProperties()) },
            {RESULT_TYPE.GROUP, new List<PropertyInfo>(new UserAccountObject().GetType().GetProperties()) },
            {RESULT_TYPE.FIREWALL, new List<PropertyInfo>(new FirewallObject().GetType().GetProperties()) },
            {RESULT_TYPE.COM, new List<PropertyInfo>(new FirewallObject().GetType().GetProperties()) },
            {RESULT_TYPE.LOG, new List<PropertyInfo>(new FirewallObject().GetType().GetProperties()) },

        };
        Dictionary<RESULT_TYPE, ANALYSIS_RESULT_TYPE> DEFAULT_RESULT_TYPE_MAP = new Dictionary<RESULT_TYPE, ANALYSIS_RESULT_TYPE>()
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

        JObject config = null;
        List<Rule> _filters = new List<Rule>();
        PLATFORM OsName;

        public Analyzer(PLATFORM platform, string filterLocation = null)
        {
            if (filterLocation == null)
            {
                LoadEmbeddedFilters();
            }
            else { 
                LoadFilters(filterLocation); 
            }

            OsName = platform;
        }

        protected void ParseFilters()
        {
            _filters = new List<Rule>();
            DEFAULT_RESULT_TYPE_MAP = new Dictionary<RESULT_TYPE, ANALYSIS_RESULT_TYPE>();
            foreach (RESULT_TYPE r in Enum.GetValues(typeof(RESULT_TYPE)))
            {
                DEFAULT_RESULT_TYPE_MAP.Add(r, ANALYSIS_RESULT_TYPE.INFORMATION);
            }
            try
            {
                foreach (var R in (JArray)config["rules"])
                {
                    _filters.Add(R.ToObject<Rule>());
                }

                foreach (var R in (JObject)config["meta"])
                {
                    switch (R.Key)
                    {
                        case "defaultLevels":
                            var loadedMap = R.Value.ToObject<Dictionary<RESULT_TYPE, ANALYSIS_RESULT_TYPE>>();
                            foreach (var kvpair in loadedMap)
                            {
                                //Overwrite the defaults with settings made (if any)
                                DEFAULT_RESULT_TYPE_MAP[kvpair.Key] = kvpair.Value;
                            }
                            break;
                    }
                }
            }
            catch (JsonException)
            {
                Log.Information(Strings.Get("Err_ParsingFilters"));
            }
        }

        public ANALYSIS_RESULT_TYPE Analyze(CompareResult compareResult)
        {
            if (compareResult == null) { return DEFAULT_RESULT_TYPE_MAP[RESULT_TYPE.UNKNOWN]; }
            if (config == null) { return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType]; }
            var results = new List<ANALYSIS_RESULT_TYPE>();
            var curFilters = _filters.Where((rule) => (rule.ChangeTypes == null || rule.ChangeTypes.Contains(compareResult.ChangeType))
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
                                        foreach (var value in (List<string>)GetValueByPropertyName(compareResult.Compare, property.Name))
                                        {
                                            valsToCheck.Add(value);
                                        }
                                    }
                                    else if (GetValueByPropertyName(compareResult.Compare, property.Name) is Dictionary<string, string>)
                                    {
                                        dictToCheck = ((Dictionary<string, string>)GetValueByPropertyName(compareResult.Compare, property.Name)).ToList();
                                    }
                                    else if (GetValueByPropertyName(compareResult.Compare, property.Name) is List<KeyValuePair<string, string>>)
                                    {
                                        dictToCheck = (List<KeyValuePair<string, string>>)GetValueByPropertyName(compareResult.Compare, property.Name);
                                    }
                                    else
                                    {
                                        valsToCheck.Add(GetValueByPropertyName(compareResult.Compare, property.Name).ToString());
                                    }
                                }
                                catch (Exception e)
                                {
                                    Log.Debug(e, "Error fetching Property {0} of Type {1}", property.Name, compareResult.ResultType);

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
                                        foreach (var value in (List<string>)GetValueByPropertyName(compareResult.Base, property.Name))
                                        {
                                            valsToCheck.Add(value);
                                        }
                                    }
                                    else if (GetValueByPropertyName(compareResult.Base, property.Name) is Dictionary<string, string>)
                                    {
                                        dictToCheck = ((Dictionary<string, string>)GetValueByPropertyName(compareResult.Base, property.Name)).ToList();
                                    }
                                    else if (GetValueByPropertyName(compareResult.Base, property.Name) is List<KeyValuePair<string, string>>)
                                    {
                                        dictToCheck = (List<KeyValuePair<string, string>>)GetValueByPropertyName(compareResult.Base, property.Name);
                                    }
                                    else
                                    {
                                        valsToCheck.Add(GetValueByPropertyName(compareResult.Base, property.Name).ToString());
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

                        int count = 0, dictCount = 0;

                        switch (clause.Operation)
                        {
                            case OPERATION.EQ:
                                foreach (string datum in clause.Data)
                                {
                                    foreach (string val in valsToCheck)
                                    {
                                        count += (datum.Equals(val)) ? 1 : 0;
                                        break;
                                    }
                                }
                                if (count == clause.Data.Count) { break; }
                                return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];

                            case OPERATION.NEQ:
                                foreach (string datum in clause.Data)
                                {
                                    foreach (string val in valsToCheck)
                                    {
                                        if (datum.Equals(val))
                                        {
                                            return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];
                                        }
                                    }
                                }
                                break;

                            case OPERATION.CONTAINS:
                                if (dictToCheck.Count > 0)
                                {
                                    foreach (KeyValuePair<string, string> value in clause.DictData)
                                    {
                                        if (dictToCheck.Where((x) => x.Key == value.Key && x.Value == value.Value).Any())
                                        {
                                            dictCount++;
                                        }
                                    }
                                    if (dictCount == clause.DictData.Count)
                                    {
                                        break;
                                    }
                                }
                                else if (valsToCheck.Count > 0)
                                {
                                    foreach (string datum in clause.Data)
                                    {
                                        foreach (string val in valsToCheck)
                                        {
                                            count += (!val.Contains(datum)) ? 1 : 0;
                                            break;
                                        }
                                    }
                                    if (count == clause.Data.Count)
                                    {
                                        break;
                                    }
                                }
                                return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];

                            case OPERATION.DOES_NOT_CONTAIN:
                                if (dictToCheck.Count > 0)
                                {
                                    foreach (KeyValuePair<string, string> value in clause.DictData)
                                    {
                                        if (dictToCheck.Where((x) => x.Key == value.Key && x.Value == value.Value).Any())
                                        {
                                            return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];
                                        }
                                    }
                                }
                                else if (valsToCheck.Count > 0)
                                {
                                    foreach (string datum in clause.Data)
                                    {
                                        if (valsToCheck.Contains(datum))
                                        {
                                            return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];
                                        }
                                    }
                                }
                                break;

                            case OPERATION.GT:
                                foreach (string val in valsToCheck)
                                {
                                    count += (int.Parse(val, CultureInfo.InvariantCulture) > int.Parse(clause.Data[0], CultureInfo.InvariantCulture)) ? 1 : 0;
                                }
                                if (count == valsToCheck.Count) { break; }
                                return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];

                            case OPERATION.LT:
                                foreach (string val in valsToCheck)
                                {
                                    count += (int.Parse(val, CultureInfo.InvariantCulture) < int.Parse(clause.Data[0], CultureInfo.InvariantCulture)) ? 1 : 0;
                                }
                                if (count == valsToCheck.Count) { break; }
                                return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];

                            case OPERATION.REGEX:
                                foreach (string val in valsToCheck)
                                {
                                    foreach (string datum in clause.Data)
                                    {
                                        var r = new Regex(datum);
                                        if (r.IsMatch(val))
                                        {
                                            count++;
                                        }
                                    }
                                }
                                if (count == valsToCheck.Count) { break; }
                                return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];

                            case OPERATION.WAS_MODIFIED:
                                if ((valsToCheck.Count == 2) && (valsToCheck[0] == valsToCheck[1]))
                                {
                                    break;
                                }
                                return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];

                            case OPERATION.ENDS_WITH:
                                foreach (string datum in clause.Data)
                                {
                                    foreach (var val in valsToCheck)
                                    {
                                        if (val.EndsWith(datum, StringComparison.CurrentCulture))
                                        {
                                            count++;
                                            break;
                                        }
                                    }
                                }
                                if (count == clause.Data.Count) { break; }
                                return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];

                            case OPERATION.STARTS_WITH:
                                foreach (string datum in clause.Data)
                                {
                                    foreach (var val in valsToCheck)
                                    {
                                        if (val.StartsWith(datum, StringComparison.CurrentCulture))
                                        {
                                            count++;
                                            break;
                                        }
                                    }
                                }
                                if (count == clause.Data.Count) { break; }
                                return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];

                            default:
                                Log.Debug("Unimplemented operation {0}", clause.Operation);
                                return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];
                        }
                    }
                    catch (Exception e)
                    {
                        Log.Debug(e, $"Hit while parsing {JsonConvert.SerializeObject(rule)} onto {JsonConvert.SerializeObject(compareResult)}");
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

        private static object GetValueByPropertyName(object obj, string propertyName) => obj.GetType().GetProperty(propertyName).GetValue(obj);


        public void DumpFilters()
        {
            Log.Verbose("Filter dump:");
            Log.Verbose(JsonConvert.SerializeObject(_filters, new StringEnumConverter()));
        }

        public void LoadEmbeddedFilters()
        {
            try
            {
                var assembly = typeof(FileSystemObject).Assembly;
                var resourceName = "AttackSurfaceAnalyzer.analyses.json";

                using (Stream stream = assembly.GetManifestResourceStream(resourceName))
                using (StreamReader streamreader = new StreamReader(stream))
                using (JsonTextReader reader = new JsonTextReader(streamreader))
                {
                    config = (JObject)JToken.ReadFrom(reader);
                    Log.Information(Strings.Get("LoadedAnalyses"), "Embedded");
                }
                if (config == null)
                {
                    Log.Debug("No filters today.");
                    return;
                }
                ParseFilters();
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

                config = null;
                Log.Debug("Could not load filters {0} {1}", "Embedded", e.GetType().ToString());

                // This is interesting. We shouldn't hit exceptions when loading the embedded resource.
                Dictionary<string, string> ExceptionEvent = new Dictionary<string, string>();
                ExceptionEvent.Add("Exception Type", e.GetType().ToString());
                AsaTelemetry.TrackEvent("EmbeddedAnalysesFilterLoadException", ExceptionEvent);
            }
        }

        public void LoadFilters(string filterLoc = null)
        {
            try
            {
                using (StreamReader file = System.IO.File.OpenText(filterLoc))
                using (JsonTextReader reader = new JsonTextReader(file))
                {
                    config = (JObject)JToken.ReadFrom(reader);
                    Log.Information(Strings.Get("LoadedAnalyses"), filterLoc);
                }
                if (config == null)
                {
                    Log.Debug("No filters this time.");
                    return;
                }
                ParseFilters();
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
                config = null;
                //Let the user know we couldn't load their file
                Log.Warning(Strings.Get("Err_MalformedFilterFile"), filterLoc);

                return;
            }
        }
    }
}


