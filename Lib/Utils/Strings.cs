using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Resources;
using System.Text;
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Properties;
using Serilog;

namespace AttackSurfaceAnalyzer.Utils
{
    public static class Strings
    {

        /// <summary>
        /// Internal member structure holding string resources
        /// </summary>
        private static Dictionary<string,string> stringList;

        public static string Get(string key)
        {
            if (stringList.ContainsKey(key))
            {
                return stringList[key];
            }
            return key;
        }

        public static void Setup(string locale = null)
        {
            if (locale == null)
            {
                stringList = new Dictionary<string, string>();

                Stream stream = typeof(FileSystemObject).Assembly.GetManifestResourceStream("AttackSurfaceAnalyzer.Properties.Resources.resources");
                ResourceReader reader = new ResourceReader(stream);
                foreach (DictionaryEntry entry in reader)
                {
                    stringList.Add(entry.Key.ToString(), entry.Value.ToString());
                }
            }
        }
    }
}
