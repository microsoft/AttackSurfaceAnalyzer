using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace AttackSurfaceAnalyzer.Utils
{
    public static class Filter
    {
        static JObject config = null;
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
                JArray filters = (JArray)config[Platform][ScanType][ItemType][Property][FilterType];
                foreach (JValue filter in filters)
                {
                    // TODO: cache these. Check Regex class cache setting
                    try
                    {
                        var testString = filter.ToString();
                        if (ItemType == "Registry")
                        {
                            testString = filter.ToString().Replace("\\", "\\\\");
                        }
                        Regex rgx = new Regex(testString);

                        if (rgx.IsMatch(Target))
                        {
                            regex = rgx;
                            Logger.Instance.Debug("{0} caught {1}", rgx, Target);
                            return true;
                        }
                    }
                    catch (Exception e)
                    {
                        Logger.Instance.Trace("Probably this is omse of those garbled keys or a bad regex");
                        Logger.Instance.Trace(e.GetType());
                        Logger.Instance.Trace(filter.ToString());

                    }

                }
            }
            catch (NullReferenceException)
            {
                Logger.Instance.Debug(JsonConvert.SerializeObject(config));
                // No filter entry for that Platform, Scantype, Itemtype, Property
                Logger.Instance.Debug("No Filter Entry {0}, {1}, {2}, {3}, {4}", Platform, ScanType, ItemType, Property, FilterType);
            }

            return false;
        }
        
        public static void LoadFilters(string filterLoc = "filters.json")
        {
            Logger.Instance.Debug("Loading filters");
            try
            {
                using (StreamReader file = File.OpenText(filterLoc))
                using (JsonTextReader reader = new JsonTextReader(file))
                {
                    config = (JObject)JToken.ReadFrom(reader);
                }
                if (config == null)
                {
                    Logger.Instance.Debug("Out of entries");
                }
            }
            catch (System.IO.FileNotFoundException)
            {
                //That's fine, we just don't have any filters to load
                Logger.Instance.Debug("{0} is missing (filter configuration file)", filterLoc);

                return;
            }
            catch (NullReferenceException)
            {
                Logger.Instance.Debug("{0} is missing (filter configuration file)", filterLoc);
                return;

            }

        }
        
    }
}
