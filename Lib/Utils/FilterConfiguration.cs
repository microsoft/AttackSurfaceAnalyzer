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
        public static bool IsFiltered(string Platform, string ScanType, string ItemType, string FilterType, string Target)
        {
            if (config == null)
            {
                return false;
            }

            JArray filters = (JArray)config[Platform][ScanType][ItemType][FilterType];
            Logger.Instance.Debug("Filter Entry {0}, {1}, {2}, {3}, {4}", Platform, ScanType, ItemType, FilterType, Target);
            Logger.Instance.Debug(JsonConvert.SerializeObject(filters));
            foreach (JValue filter in filters)
            {
                // TODO: cache these. Check Regex class cache setting
                Regex rgx = new Regex(filter.ToString());
                if (rgx.IsMatch(Target))
                {
                    return true;
                }
            }
            return false;
        }
        
        public static void LoadFilters(string filterLoc = "filters.json")
        {
            using (StreamReader file = File.OpenText(filterLoc))
            using (JsonTextReader reader = new JsonTextReader(file))
            {
                config = (JObject)JToken.ReadFrom(reader);
            }
            if (config == null)
            {
                Logger.Instance.Debug("{0} is missing (filter configuration file)",filterLoc);
            }
        }
        
    }
}
