using AttackSurfaceAnalyzer.Objects;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Serilog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace AttackSurfaceAnalyzer.Utils
{
    public static class Filter
    {
        static JObject config = null;
        static Dictionary<string, List<Regex>> _filters = new Dictionary<string, List<Regex>>() {
            { "Certificates:Scan:File:Path:Include",new List<Regex>(){ new Regex("^.*\\.cer$") } },
            { "Certificates:Scan:File:Path:Exclude",new List<Regex>(){ new Regex(".*") } }
        };

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
                string key = $"{Platform}:{ScanType}:{ItemType}:{Property}:{FilterType}";
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
                            filters.Add(new Regex(filter.ToString(), RegexOptions.Compiled));
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
                        Log.Verbose(Strings.Get("SuccessParsed"), Platform, ScanType, ItemType, Property, FilterType);
                    }
                    catch (Exception e) when (
                        e is NullReferenceException
                        || e is JsonReaderException)
                    { 
                        try
                        {
                            _filters.Add(key, new List<Regex>());
                            Log.Verbose(Strings.Get("EmptyEntry"), Platform, ScanType, ItemType, Property, FilterType);
                        }
                        catch(Exception ex) when (
                            ex is ArgumentNullException
                            || ex is ArgumentException)
                        {
                            // We are running in parallel, its possible someone added it in between the original check and now. No problem here.
                        }

                        //Since there were no filters for this, it is not filtered
                        return false;
                    }
                }

                foreach (Regex filter in _filters[key])
                {
                    if (filter.IsMatch(Target))
                    {
                        regex = filter;
                        Log.Verbose("{0} caught {1}", filter, Target);
                        return true;
                    }
                }
            }
            catch (NullReferenceException)
            {
                Log.Debug("No Filter Entry {0}, {1}, {2}, {3}, {4}", Platform, ScanType, ItemType, Property, FilterType);
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

        public static void LoadEmbeddedFilters()
        {
            try
            {
                var assembly = typeof(FileSystemObject).Assembly;
                var resourceName = "AttackSurfaceAnalyzer.filters.json";

                using (Stream stream = assembly.GetManifestResourceStream(resourceName))
                using (StreamReader streamreader = new StreamReader(stream))
                using (JsonTextReader reader = new JsonTextReader(streamreader))
                {
                    config = (JObject)JToken.ReadFrom(reader);
                    Log.Information(Strings.Get("LoadedFilters"), "Embedded");
                    DumpFilters();
                }
                if (config == null)
                {
                    Log.Debug("Out of entries");
                }
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
                AsaTelemetry.TrackEvent("EmbeddedFilterLoadException", ExceptionEvent);
                return;
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
                    Log.Information(Strings.Get("LoadedFilters"), filterLoc);
                    DumpFilters();
                }
                if (config == null)
                {
                    Log.Debug("Out of entries");
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
                config = null;
                //Let the user know we couldn't load their file
                Log.Warning(Strings.Get("Err_MalformedFilterFile"),filterLoc);

                return;
            }
        }
    }
}
