﻿using Newtonsoft.Json;
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
        public static string RuntimeString()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                return "Linux";
            }
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return "Windows";
            }
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return "Macos";
            }
            return "Unknown";
        }

        public static bool IsFiltered(string Platform, string ScanType, string ItemType, string Property, string Target)
        {
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
                        Log.Debug(jFilters.ToString());
                        foreach (var filter in jFilters)
                        {
                            Log.Debug(filter.ToString());
                            filters.Add(new Regex(filter.ToString()));
                        }
                        _filters.Add(key, filters);
                        Log.Warning("Successfully parsed {0} {1} {2} {3} {4}", Platform, ScanType, ItemType, Property, FilterType);
                    }
                    catch (NullReferenceException)
                    {
                        //Log.Debug(ex.GetType().ToString());
                        //Log.Debug(ex.Message);
                        //Log.Debug(ex.StackTrace);
                        //Log.Debug("Failed adding");
                        Log.Debug("Failed parsing {0} {1} {2} {3} {4} (no entry?)", Platform, ScanType, ItemType, Property, FilterType);
                        _filters.Add(key, new List<Regex>());
                        return false;
                    }
                }
                catch (Exception e)
                {
                    Log.Debug(e.GetType().ToString());
                    Log.Debug(e.Message);
                    Log.Debug(e.StackTrace);
                }

                Log.Verbose("We are making it past. {0}{1}{2}{3}{4}",Platform,ScanType,ItemType,Property,FilterType);
                //JArray filters = (JArray)config[Platform][ScanType][ItemType][Property][FilterType];
                foreach (Regex filter in _filters[key])
                {
                    try
                    {
                        if (filter.IsMatch(Target))
                        {
                            regex = filter;
                            Log.Debug("{0} caught {1}", filter, Target);
                            return true;
                        }
                    }
                    catch (Exception e)
                    {
                        Log.Debug("Probably this is some of those garbled keys or a bad regex");
                        Log.Debug(e.GetType().ToString());
                        Log.Debug(filter.ToString());

                    }

                }
            }
            catch (NullReferenceException e)
            {
                //Log.Verbose(JsonConvert.SerializeObject(config));
                // No filter entry for that Platform, Scantype, Itemtype, Property
                Log.Debug("No Filter Entry {0}, {1}, {2}, {3}, {4}", Platform, ScanType, ItemType, Property, FilterType);
                Log.Debug(e.Message);
                Log.Debug(e.Source);
                Log.Debug(e.StackTrace);
            }

            return false;
        }

        public static void DumpFilters()
        {
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
                    Log.Information("Loaded filters from {0}", filterLoc);
                }
                if (config == null)
                {
                    Log.Debug("Out of entries");
                }
            }
            catch (System.IO.FileNotFoundException)
            {
                //That's fine, we just don't have any filters to load
                Log.Debug("{0} is missing (filter configuration file)", filterLoc);

                return;
            }
            catch (NullReferenceException)
            {

                Log.Debug("{0} is missing (filter configuration file)", filterLoc);

                return;

            }

        }
        
    }
}
