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
        Dictionary<RESULT_TYPE,List<FieldInfo>> _Fields;


        JObject config = null;
        Dictionary<string, Dictionary<string, List<Rule>>> _filters = new Dictionary<string, Dictionary<string,List<Rule>>>();
        string OsName;
        ANALYSIS_RESULT_TYPE DEFAULT_RESULT_TYPE;

        Dictionary<RESULT_TYPE,List<Rule>> rules;

        public Analyzer() : this(useEmbedded:true) { }
        public Analyzer(string filterLocation = "filters.json", bool useEmbedded = false, ANALYSIS_RESULT_TYPE defaultResultType = ANALYSIS_RESULT_TYPE.INFORMATION) {
            if (useEmbedded) { LoadEmbeddedFilters(); }
            else { LoadFilters(filterLocation); }
            if (config != null) { ParseFilters(); }
            DEFAULT_RESULT_TYPE = defaultResultType;
            PopulateFields();
        }

        protected void ParseFilters()
        {
            foreach (string o in Enum.GetNames(typeof(OSPlatform)))
            {
                _filters[o] = new Dictionary<string, List<Rule>>();
                foreach (string t in Enum.GetNames(typeof(RESULT_TYPE)))
                {
                    _filters[o][t] = new List<Rule>();
                }
                try
                {
                    JArray jFilters = (JArray)config[o];
                    foreach (var R in jFilters)
                    {
                        Rule r = R.ToObject<Rule>();
                        _filters[o][r.resultType.ToString()].Add(r);
                    }
                }
                catch(Exception e)
                {
                    Log.Debug("{0} {1} {2}", e.GetType().ToString(), e.Message, e.StackTrace);
                }
            }
        }

        protected void PopulateFields()
        {
            _Fields[RESULT_TYPE.FILE] = new List<FieldInfo>(new FileSystemObject().GetType().GetFields());
            _Fields[RESULT_TYPE.CERTIFICATE] = new List<FieldInfo>(new CertificateObject().GetType().GetFields());
            _Fields[RESULT_TYPE.PORT] = new List<FieldInfo>(new OpenPortObject().GetType().GetFields());
            _Fields[RESULT_TYPE.REGISTRY] = new List<FieldInfo>(new RegistryObject().GetType().GetFields());
            _Fields[RESULT_TYPE.SERVICES] = new List<FieldInfo>(new ServiceObject().GetType().GetFields());
            _Fields[RESULT_TYPE.USER] = new List<FieldInfo>(new UserAccountObject().GetType().GetFields());
        }

        public ANALYSIS_RESULT_TYPE Analyze(CompareResult compareResult)
        {
            if (config == null) { return DEFAULT_RESULT_TYPE; }
            RESULT_TYPE ruleFilter = compareResult.ResultType;

            foreach (Rule rule in rules[compareResult.ResultType])
            {
                var next = Apply(rule, compareResult);
                if (next != DEFAULT_RESULT_TYPE) { return next; }
            }

            return DEFAULT_RESULT_TYPE;
        }

        protected ANALYSIS_RESULT_TYPE Apply(Rule rule, CompareResult compareResult)
        {
            var fields = _Fields[compareResult.ResultType];

            foreach (Clause clause in rule.clauses)
            {
                FieldInfo field = fields.FirstOrDefault(iField => iField.Name.Equals(clause.field));

                if (field == null)
                {
                    //Custom field logic
                    return DEFAULT_RESULT_TYPE;
                }
                else
                {
                    var val = default(object);
                    var baseVal = default(object);
                    try
                    {
                        if (compareResult.Compare != null)
                        {
                            val = GetValueByPropertyName(compareResult.Compare, field.Name);
                        }
                        if (compareResult.Base != null)
                        {
                            baseVal = GetValueByPropertyName(compareResult.Base, field.Name);
                        }
                        var complete = false;

                        switch (clause.op)
                        {
                            case OPERATION.EQ:
                                foreach (string datum in clause.data)
                                {
                                    if (datum.Equals(val))
                                    {
                                        complete = true;
                                    }
                                }
                                if (complete) { break; }
                                return DEFAULT_RESULT_TYPE;

                            case OPERATION.NEQ:
                                foreach (string datum in clause.data)
                                {
                                    if (!datum.Equals(val))
                                    {
                                        complete = true;
                                    }
                                }
                                if (complete) { break; }
                                return DEFAULT_RESULT_TYPE;

                            case OPERATION.CONTAINS:
                                foreach (string datum in clause.data)
                                {
                                    var fld = GetValueByPropertyName(compareResult.Compare, field.Name).ToString();
                                    if (fld.Contains(datum))
                                    {
                                        complete = true;
                                    }
                                }
                                if (complete) { break; }
                                return DEFAULT_RESULT_TYPE;

                            case OPERATION.GT:
                                if (Int32.Parse(val.ToString()) > Int32.Parse(clause.data[0]))
                                {
                                    break;
                                }
                                return DEFAULT_RESULT_TYPE;

                            case OPERATION.LT:
                                if (Int32.Parse(val.ToString()) < Int32.Parse(clause.data[0]))
                                {
                                    break;
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
                                if (complete) { break ; }
                                return DEFAULT_RESULT_TYPE;
                            case OPERATION.WAS_MODIFIED:
                                if (!val.ToString().Equals(baseVal.ToString()))
                                {
                                    break;
                                }
                                return DEFAULT_RESULT_TYPE;
                            default:
                                Log.Debug("Unimplemented operation {0}", clause.op);
                                break;
                        }
                    }
                    catch (Exception e)
                    {
                        Log.Debug("{0} {1} {2}", e.GetType().ToString(), e.Message, e.StackTrace);
                        return DEFAULT_RESULT_TYPE;
                    }
                }
            }

            return rule.flag;
        }

        private object GetValueByPropertyName<T>(T obj, string propertyName)
        {
            return typeof(T).GetProperty(propertyName).GetValue(obj);
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

        public void LoadFilters(string filterLoc = "analyses.json")
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


