using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Serilog;

namespace AttackSurfaceAnalyzer.Utils
{
    public static class Filter
    {
        static JObject config = null;
        static Dictionary<string, List<Regex>> _filters = new Dictionary<string, List<Regex>>();

        public static bool IsFiltered(string Platform, string ScanType, string ItemType, string Property, string Target)
        {
            if (config == null)
            {
                return false;
            }
            if (IsFiltered(Platform, ScanType, ItemType, Property, "Include", Target))
            {
                return false;
            }
            return IsFiltered(Platform, ScanType, ItemType, Property, "Exclude", Target);
        }

        public static bool IsFiltered(string Platform, string ScanType, string ItemType, string Property, string FilterType, string Target) => IsFiltered(Platform, ScanType, ItemType, Property, FilterType, Target, out Regex dummy);

        public static bool IsFiltered(string Platform, string ScanType, string ItemType, string Property, string FilterType, string Target, out Regex regex)
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
                            _filters.Add(key, filters);
                            Log.Debug("{0} {1} {2} {3} {4} {5}", Strings.Get("FailedParsed"), Platform, ScanType, ItemType, Property, FilterType);
                        }
                        catch (ArgumentException)
                        {
                            // We are running in parallel, its possible someone added it in between the original check and now. No problem here.
                        }
                        return false;
                    }
                    catch (JsonReaderException)
                    {
                        try
                        {
                            _filters.Add(key, filters);
                            Log.Information("{0} {1} {2} {3} {4} {5}", Strings.Get("Err_FiltersFile"), Platform, ScanType, ItemType, Property, FilterType);
                        }
                        catch (ArgumentException)
                        {
                            // We are running in parallel, its possible someone added it in between the original check and now. No problem here.
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

        public static void DumpFilters()
        {
            Log.Verbose("Filter dump:");
            foreach (var filter in config)
            {
                Log.Verbose(filter.Value.ToString());
            }
        }

        public static void LoadFilters(string filterLoc = "filters.json")
        {
            try
            {
                using (StreamReader file = File.OpenText(filterLoc))
                using (JsonTextReader reader = new JsonTextReader(file))
                {
                    config = (JObject)JToken.ReadFrom(reader);
                    Log.Information("{0} {1}",Strings.Get("LoadedFilters"), filterLoc);
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
                Log.Debug("{0} is missing (filter configuration file)", filterLoc);

                return;
            }
            catch (NullReferenceException)
            {
                config = null;
                Log.Debug("{0} is missing (filter configuration file)", filterLoc);

                return;

            }

        }
        
    }
}
