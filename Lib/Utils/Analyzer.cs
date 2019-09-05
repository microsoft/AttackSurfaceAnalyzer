using System;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using Serilog;
using System.Reflection;
using AttackSurfaceAnalyzer.Objects;
using System.Runtime.InteropServices;
using System.Linq;
using Newtonsoft.Json.Converters;
using PeNet.Structures.MetaDataTables;
using Markdig.Extensions.Tables;
using AttackSurfaceAnalyzer.Types;

namespace AttackSurfaceAnalyzer.Utils
{
    public class Analyzer
    {
        Dictionary<RESULT_TYPE, List<FieldInfo>> _Fields = new Dictionary<RESULT_TYPE, List<FieldInfo>>()
        {
            {RESULT_TYPE.FILE , new List<FieldInfo>(new FileSystemObject().GetType().GetFields()) },
            {RESULT_TYPE.CERTIFICATE, new List<FieldInfo>(new CertificateObject().GetType().GetFields()) },
            {RESULT_TYPE.PORT, new List<FieldInfo>(new OpenPortObject().GetType().GetFields()) },
            {RESULT_TYPE.REGISTRY, new List<FieldInfo>(new RegistryObject().GetType().GetFields()) },
            {RESULT_TYPE.SERVICE, new List<FieldInfo>(new ServiceObject().GetType().GetFields()) },
            {RESULT_TYPE.USER, new List<FieldInfo>(new UserAccountObject().GetType().GetFields()) },
            {RESULT_TYPE.GROUP, new List<FieldInfo>(new UserAccountObject().GetType().GetFields()) },
            {RESULT_TYPE.FIREWALL, new List<FieldInfo>(new FirewallObject().GetType().GetFields()) },
        };
        Dictionary<RESULT_TYPE, List<PropertyInfo>> _Properties = new Dictionary<RESULT_TYPE, List<PropertyInfo>>()
        {
            {RESULT_TYPE.FILE , new List<PropertyInfo>(new FileSystemObject().GetType().GetProperties()) },
            {RESULT_TYPE.CERTIFICATE, new List<PropertyInfo>(new CertificateObject().GetType().GetProperties()) },
            {RESULT_TYPE.PORT, new List<PropertyInfo>(new OpenPortObject().GetType().GetProperties()) },
            {RESULT_TYPE.REGISTRY, new List<PropertyInfo>(new RegistryObject().GetType().GetProperties()) },
            {RESULT_TYPE.SERVICE, new List<PropertyInfo>(new ServiceObject().GetType().GetProperties()) },
            {RESULT_TYPE.USER, new List<PropertyInfo>(new UserAccountObject().GetType().GetProperties()) },
            {RESULT_TYPE.GROUP, new List<PropertyInfo>(new UserAccountObject().GetType().GetProperties()) },
            {RESULT_TYPE.FIREWALL, new List<PropertyInfo>(new FirewallObject().GetType().GetProperties()) }

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
            { RESULT_TYPE.GROUP, ANALYSIS_RESULT_TYPE.INFORMATION }
        };

        JObject config = null;
        List<Rule> _filters = new List<Rule>();
        PLATFORM OsName;

        public Analyzer(PLATFORM platform, string filterLocation = null)
        {
            if (filterLocation == null) { LoadEmbeddedFilters(); }
            else { LoadFilters(filterLocation); }

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
            catch (Exception e)
            {
                Logger.DebugException(e);
            }
        }

        public ANALYSIS_RESULT_TYPE Analyze(CompareResult compareResult)
        {
            if (config == null) { return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType]; }
            var results = new List<ANALYSIS_RESULT_TYPE>();
            var curFilters = _filters.Where((rule) => (rule.changeTypes.Contains(compareResult.ChangeType) || rule.changeTypes == null)
                                                     && (rule.platforms.Contains(OsName) || rule.platforms == null)
                                                     && (rule.resultType.Equals(compareResult.ResultType)))
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

        protected ANALYSIS_RESULT_TYPE Apply(Rule rule, CompareResult compareResult)
        {
            var fields = _Fields[compareResult.ResultType];
            var properties = _Properties[compareResult.ResultType];

            foreach (Clause clause in rule.clauses)
            {
                FieldInfo field = fields.FirstOrDefault(iField => iField.Name.Equals(clause.field));
                PropertyInfo property = properties.FirstOrDefault(iProp => iProp.Name.Equals(clause.field));
                if (field == null && property == null)
                {
                    //Custom field logic will go here
                    return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];
                }

                try
                {
                    var complete = false;
                    var valsToCheck = new List<string>();

                    if (compareResult.ChangeType == CHANGE_TYPE.CREATED || compareResult.ChangeType == CHANGE_TYPE.MODIFIED)
                    {
                        try
                        {
                            valsToCheck.Add(GetValueByFieldName(compareResult.Compare, field.Name).ToString());
                        }
                        catch (NullReferenceException)
                        {
                        }
                        try
                        {
                            valsToCheck.Add(GetValueByPropertyName(compareResult.Compare, property.Name).ToString());
                        }
                        catch (NullReferenceException)
                        {
                        }

                    }
                    if (compareResult.ChangeType == CHANGE_TYPE.DELETED || compareResult.ChangeType == CHANGE_TYPE.MODIFIED)
                    {
                        try
                        {
                            valsToCheck.Add(GetValueByFieldName(compareResult.Base, field.Name).ToString());
                        }
                        catch (NullReferenceException)
                        {
                        }
                        try
                        {
                            valsToCheck.Add(GetValueByPropertyName(compareResult.Base, property.Name).ToString());
                        }
                        catch (NullReferenceException)
                        {
                        }
                    }

                    switch (clause.op)
                    {
                        case OPERATION.EQ:
                            foreach (string datum in clause.data)
                            {
                                foreach (string val in valsToCheck)
                                {
                                    complete |= datum.Equals(val);
                                }
                            }
                            if (complete) { break; }
                            return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];

                        case OPERATION.NEQ:
                            foreach (string datum in clause.data)
                            {
                                foreach (string val in valsToCheck)
                                {
                                    complete |= !datum.Equals(val);
                                }
                            }
                            if (complete) { break; }
                            return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];

                        case OPERATION.CONTAINS:
                            foreach (string datum in clause.data)
                            {
                                foreach (string val in valsToCheck)
                                {
                                    complete |= val.Contains(datum);
                                }
                            }
                            if (complete) { break; }
                            return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];

                        case OPERATION.GT:
                            foreach (string val in valsToCheck)
                            {
                                complete |= Int32.Parse(val.ToString()) > Int32.Parse(clause.data[0]);
                            }
                            if (complete) { break; }
                            return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];

                        case OPERATION.LT:
                            foreach (string val in valsToCheck)
                            {
                                complete |= Int32.Parse(val.ToString()) < Int32.Parse(clause.data[0]);
                            }
                            if (complete) { break; }

                            return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];

                        case OPERATION.REGEX:
                            foreach (string val in valsToCheck)
                            {
                                foreach (string datum in clause.data)
                                {
                                    var r = new Regex(datum);
                                    if (r.IsMatch(val))
                                    {
                                        complete = true;
                                    }
                                }
                            }
                            if (complete) { break; }
                            return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];
                        case OPERATION.WAS_MODIFIED:
                            if ((valsToCheck.Count == 2) && (valsToCheck[0] == valsToCheck[1]))
                            {
                                break;
                            }
                            return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];
                        case OPERATION.ENDS_WITH:
                            foreach (string datum in clause.data)
                            {
                                foreach (var val in valsToCheck)
                                {
                                    if (val.EndsWith(datum, StringComparison.CurrentCulture))
                                    {
                                        complete = true;
                                        break;
                                    }
                                }
                                if (complete) { break; }
                            }
                            if (complete) { break; }
                            return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];
                        case OPERATION.STARTS_WITH:
                            foreach (string datum in clause.data)
                            {
                                foreach (var val in valsToCheck)
                                {
                                    if (val.StartsWith(datum, StringComparison.CurrentCulture))
                                    {
                                        complete = true;
                                        break;
                                    }
                                }
                                if (complete) { break; }
                            }
                            if (complete) { break; }
                            return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];
                        default:
                            Log.Debug("Unimplemented operation {0}", clause.op);
                            return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];
                    }
                }
                catch (Exception e)
                {
                    Logger.DebugException(e);
                    return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];
                }
            }
            compareResult.Rules.Add(rule);
            return rule.flag;
        }

        private object GetValueByFieldName(object obj, string fieldName) => obj.GetType().GetField(fieldName).GetValue(obj);
        private object GetValueByPropertyName(object obj, string propertyName) => obj.GetType().GetField(propertyName).GetValue(obj);


        public void DumpFilters()
        {
            Log.Verbose("Filter dump:");
            Log.Verbose(JsonConvert.SerializeObject(_filters, new StringEnumConverter()));
        }

        public void LoadEmbeddedFilters()
        {
            try
            {
                var assembly = System.Reflection.Assembly.GetExecutingAssembly();
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
            catch (FileNotFoundException)
            {
                config = null;
                Log.Debug("{0} is missing (filter configuration file)", "Embedded");

                return;
            }
            catch (NullReferenceException)
            {
                config = null;
                Log.Debug("{0} is missing (filter configuration file)", "Embedded");

                return;
            }
            catch (JsonReaderException)
            {
                config = null;
                Log.Warning("Error when parsing '{0}' analyses file. This is likely an issue with your JSON formatting.", "Embedded");
            }
            catch (Exception e)
            {
                config = null;
                Log.Warning("Could not load filters {0} {1} {2}", "Embedded", e.GetType().ToString(), e.StackTrace);

                return;
            }
        }

        public void LoadFilters(string filterLoc = "analyses.json")
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
            catch (System.IO.FileNotFoundException)
            {
                //That's fine, we just don't have any filters to load
                config = null;
                Log.Warning("{0} is missing (filter configuration file)", filterLoc);

                return;
            }
            catch (NullReferenceException)
            {
                config = null;
                Log.Warning("{0} is missing (filter configuration file)", filterLoc);

                return;
            }
            catch (JsonReaderException)
            {
                config = null;
                Log.Warning("Error when parsing '{0}' analyses file. This is likely an issue with your JSON formatting.", filterLoc);
            }
            catch (Exception e)
            {
                config = null;
                Log.Warning("Could not load filters {0} {1} {2}", filterLoc, e.GetType().ToString(), e.StackTrace);
                return;
            }
        }
    }
}


