using System;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using Serilog;
using System.Reflection;
using AttackSurfaceAnalyzer.ObjectTypes;
using System.Runtime.InteropServices;
using System.Linq;

namespace AttackSurfaceAnalyzer.Utils
{

    public class Rule
    {
        public string name;
        public ANALYSIS_RESULT_TYPE flag;
        public OSPlatform platform;
        public RESULT_TYPE resultType;
        public List<Clause> clauses;
    }

    public class Clause
    {
        public string field;
        public OPERATION op;
        public List<string> data;
    }

    public class Analyzer
    {
        Dictionary<RESULT_TYPE,List<FieldInfo>> fields;


        JObject config = null;
        Dictionary<string, List<Regex>> _filters = new Dictionary<string, List<Regex>>();
        string OsName;
        ANALYSIS_RESULT_TYPE DEFAULT_RESULT_TYPE;

        Dictionary<RESULT_TYPE,List<Rule>> rules;

        public Analyzer() : this(useEmbedded:true) { }
        public Analyzer(string filterLocation = "filters.json", bool useEmbedded = false, ANALYSIS_RESULT_TYPE defaultResultType = ANALYSIS_RESULT_TYPE.INFORMATION) {
            if (useEmbedded) { LoadEmbeddedFilters(); }
            else { LoadFilters(filterLocation); }
            DEFAULT_RESULT_TYPE = defaultResultType;
            populateFields();
        }

        protected void populateFields()
        {
            fields[RESULT_TYPE.FILE] = new List<FieldInfo>(new FileSystemObject().GetType().GetFields());
            fields[RESULT_TYPE.CERTIFICATE] = new List<FieldInfo>(new CertificateObject().GetType().GetFields());
            fields[RESULT_TYPE.PORT] = new List<FieldInfo>(new OpenPortObject().GetType().GetFields());
            fields[RESULT_TYPE.REGISTRY] = new List<FieldInfo>(new RegistryObject().GetType().GetFields());
            fields[RESULT_TYPE.SERVICES] = new List<FieldInfo>(new ServiceObject().GetType().GetFields());
            fields[RESULT_TYPE.USER] = new List<FieldInfo>(new UserAccountObject().GetType().GetFields());
        }

        public  ANALYSIS_RESULT_TYPE Analyze(CompareResult compareResult)
        {
            RESULT_TYPE ruleFilter = compareResult.ResultType;
            
            var Rules = rules[ruleFilter];
            var current = DEFAULT_RESULT_TYPE;

            foreach (Rule rule in Rules)
            {
                var next = Apply(rule, compareResult);
                if (next != DEFAULT_RESULT_TYPE) { return next; }
            }

            return current;
        }

        protected ANALYSIS_RESULT_TYPE Apply(Rule rule, CompareResult compareResult)
        {
            switch (compareResult)
            {
                case CertificateResult res:
                    return ApplyCertificateRule(rule, res);
                case FileSystemResult res:
                    return ApplyFileRule(rule, res);
                case OpenPortResult res:
                    return ApplyPortRule(rule, res);
                case UserAccountResult res:
                    return ApplyUserRule(rule, res);
                case RegistryResult res:
                    return ApplyRegistryRule(rule, res);
                case ServiceResult res:
                    return ApplyServiceRule(rule, res);
            }
            return DEFAULT_RESULT_TYPE;
        }

        private object GetValueByPropertyName<T>(T obj, string propertyName)
        {
            return typeof(T).GetProperty(propertyName).GetValue(obj);
        }

        protected ANALYSIS_RESULT_TYPE ApplyCertificateRule(Rule rule, CertificateResult res)
        {
            List<FieldInfo> fields = new List<FieldInfo>(res.Compare.GetType().GetFields());
            if (fields == null)
            {
                fields = new List<FieldInfo>(res.Base.GetType().GetFields());
            }

            foreach (Clause clause in rule.clauses)
            {
                FieldInfo field = fields.FirstOrDefault(iField => iField.Name.Equals(clause.field));

                if (field == null)
                {
                    //Custom field logic
                }
                else
                {
                    var val = GetValueByPropertyName(res.Compare, field.Name);
                    var complete = false;

                    switch (clause.op)
                    {
                        case OPERATION.EQ:
                            foreach (string datum in clause.data)
                            {
                                if (clause.data.Equals(val))
                                {
                                    complete = true;
                                }
                            }
                            if (complete) { continue; }
                            return DEFAULT_RESULT_TYPE;

                        case OPERATION.NEQ:
                            foreach (string datum in clause.data)
                            {
                                if (!clause.data.Equals(val))
                                {
                                    complete = true;
                                }
                            }
                            if (complete) { continue; }
                            return DEFAULT_RESULT_TYPE;

                        case OPERATION.CONTAINS:
                            foreach (string datum in clause.data)
                            {
                                var fld = GetValueByPropertyName(res.Compare, field.Name).ToString();
                                if (fld.Contains(datum))
                                {
                                    complete = true;
                                }
                            }
                            if (complete) { continue; }
                            return DEFAULT_RESULT_TYPE;

                        case OPERATION.GT:
                            if (Int32.Parse(val.ToString()) > Int32.Parse(clause.data[0]))
                            {
                                continue;
                            }
                            return DEFAULT_RESULT_TYPE;

                        case OPERATION.LT:
                            if (Int32.Parse(val.ToString()) < Int32.Parse(clause.data[0]))
                            {
                                continue;
                            }
                            return DEFAULT_RESULT_TYPE;

                        case OPERATION.REGEX:
                            foreach (string datum in clause.data)
                            {
                                var r = new Regex(datum);
                                if (r.IsMatch(val.ToString()))
                                {
                                    complete = true;
                                }
                            }
                            if (complete) { continue; }
                            return DEFAULT_RESULT_TYPE;
                        default:
                            Log.Debug("Unimplemented operation {0}", clause.op);
                            break;
                    }
                }
            }

            return rule.flag;
        }

        public  bool IsFiltered(string Platform, string ScanType, string ItemType, string Property, string FilterType, string Target) => IsFiltered(Platform, ScanType, ItemType, Property, FilterType, Target, out Regex dummy);

        public  bool IsFiltered(string Platform, string ScanType, string ItemType, string Property, string FilterType, string Target, out Regex regex)
        {
            regex = null;
            if (config == null)
            {
                return false;
            }
            try
            {
                string key = String.Format("{0}{1}{2}{3}{4}", Platform, ScanType, ItemType, Property, FilterType);
                List<Regex> filters = new List<Regex>();

                try
                {
                    filters = _filters[key];
                }
                catch (KeyNotFoundException)
                {
                    try
                    {
                        JArray jFilters = (JArray)config[Platform][ScanType][ItemType][Property][FilterType];
                        foreach (var filter in jFilters)
                        {
                            try
                            {
                                filters.Add(new Regex(filter.ToString()));
                            }
                            catch (Exception e)
                            {
                                Log.Debug(e.GetType().ToString());
                                Log.Debug("Failed to make a regex from {0}", filter.ToString());
                                Telemetry.TrackTrace(Microsoft.ApplicationInsights.DataContracts.SeverityLevel.Error, e);
                            }
                        }
                        try
                        {
                            _filters.Add(key, filters);
                        }
                        catch (ArgumentException)
                        {
                            // We are running in parallel, its possible someone added it in between the original check and now. No problem here.
                            filters = _filters[key];
                        }
                        Log.Information("{0} {1} {2} {3} {4} {5}", Strings.Get("SuccessParsed"), Platform, ScanType, ItemType, Property, FilterType);
                    }
                    catch (NullReferenceException)
                    {
                        try
                        {
                            _filters.Add(key, new List<Regex>());
                            Log.Debug("{0} {1} {2} {3} {4} {5}", Strings.Get("FailedParsed"), Platform, ScanType, ItemType, Property, FilterType);
                        }
                        catch (ArgumentException)
                        {
                            // We are running in parallel, its possible someone added it in between the original check and now. No problem here.
                        }
                        catch (Exception e)
                        {
                            Log.Debug("{0}:{1}", e.GetType().ToString(), e.Message);
                            Log.Debug(e.StackTrace);
                        }

                        //Since there were no filters for this, it is not filtered
                        return false;
                    }
                    catch (JsonReaderException)
                    {
                        try
                        {
                            _filters.Add(key, new List<Regex>());
                            Log.Information("{0} {1} {2} {3} {4} {5}", Strings.Get("Err_FiltersFile"), Platform, ScanType, ItemType, Property, FilterType);
                        }
                        catch (ArgumentException)
                        {
                            // We are running in parallel, its possible someone added it in between the original check and now. No problem here.
                        }
                        catch (Exception e)
                        {
                            Log.Debug("{0}:{1}", e.GetType().ToString(), e.Message);
                            Log.Debug(e.StackTrace);
                        }
                        return false;
                    }

                }
                catch (Exception e)
                {
                    Log.Debug(e.GetType().ToString());
                    Log.Debug(e.Message);
                    Log.Debug(e.StackTrace);
                    Telemetry.TrackTrace(Microsoft.ApplicationInsights.DataContracts.SeverityLevel.Error, e);
                }

                foreach (Regex filter in _filters[key])
                {
                    try
                    {
                        if (filter.IsMatch(Target))
                        {
                            regex = filter;
                            Log.Verbose("{0} caught {1}", filter, Target);
                            return true;
                        }
                    }
                    catch (Exception e)
                    {
                        Log.Debug("Probably this is some of those garbled keys or a bad regex");
                        Log.Debug(e.GetType().ToString());
                        Log.Debug(filter.ToString());
                        Telemetry.TrackTrace(Microsoft.ApplicationInsights.DataContracts.SeverityLevel.Error, e);
                    }

                }
            }
            catch (NullReferenceException e)
            {
                Log.Debug("No Filter Entry {0}, {1}, {2}, {3}, {4}", Platform, ScanType, ItemType, Property, FilterType);
                Log.Debug(e.Message);
                Log.Debug(e.Source);
                Log.Debug(e.StackTrace);
            }

            return false;
        }

        public  void DumpFilters()
        {
            Log.Verbose("Filter dump:");
            foreach (var filter in config)
            {
                Log.Verbose(filter.Value.ToString());
            }
        }

        public  void LoadEmbeddedFilters()
        {
            try
            {
                var assembly = Assembly.GetExecutingAssembly();
                var resourceName = "AttackSurfaceAnalyzer.analyses.json";

                using (Stream stream = assembly.GetManifestResourceStream(resourceName))
                using (StreamReader streamreader = new StreamReader(stream))
                using (JsonTextReader reader = new JsonTextReader(streamreader))
                {
                    config = (JObject)JToken.ReadFrom(reader);
                    Log.Information(Strings.Get("LoadedAnalyses"), "Embedded");
                    DumpFilters();
                }
                if (config == null)
                {
                    Log.Debug("Out of entries");
                }
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
            catch (Exception e)
            {
                config = null;
                Log.Warning("Could not load filters {0} {1}", "Embedded", e.GetType().ToString());

                return;
            }
        }

        public  void LoadFilters(string filterLoc = "filters.json")
        {
            try
            {
                using (StreamReader file = File.OpenText(filterLoc))
                using (JsonTextReader reader = new JsonTextReader(file))
                {
                    config = (JObject)JToken.ReadFrom(reader);
                    Log.Information(Strings.Get("LoadedAnalyses"), filterLoc);
                    DumpFilters();
                }
                if (config == null)
                {
                    Log.Debug("Out of entries");
                }
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
            catch (Exception e)
            {
                config = null;
                Log.Warning("Could not load filters {0} {1}", filterLoc, e.GetType().ToString());
                return;
            }
        }
    }
}


