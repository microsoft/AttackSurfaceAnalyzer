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
        public static bool IsFiltered(string Platform, string ScanType, string ItemType, string Property, string FilterType, string Target)
        {
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
                    Regex rgx = new Regex(filter.ToString());
                    if (rgx.IsMatch(Target))
                    {
                        Logger.Instance.Debug("{0} caught {1}", rgx, Target);
                        return true;
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

        }
        
    }
}
