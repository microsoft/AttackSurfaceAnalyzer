// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Resources;

namespace AttackSurfaceAnalyzer.Utils
{
    public static class Strings
    {

        /// <summary>
        /// Internal member structure holding string resources
        /// </summary>
        private static Dictionary<string, string> stringList = new Dictionary<string, string>();

        public static string Get(string key)
        {
            if (stringList.ContainsKey(key))
            {
                return stringList[key];
            }
            return key;
        }

        public static void Setup(string locale = "")
        {
            if (string.IsNullOrEmpty(locale))
            {
                using Stream stream = typeof(FileSystemObject).Assembly.GetManifestResourceStream("AttackSurfaceAnalyzer.Properties.Resources.resources") ?? new MemoryStream();
                using ResourceReader reader = new ResourceReader(stream);
                foreach (DictionaryEntry? entry in reader)
                {
                    if (entry is DictionaryEntry dictionaryEntry)
                    {
                        var keyStr = dictionaryEntry.Key.ToString();
                        var valueStr = dictionaryEntry.Value?.ToString();
                        if (!string.IsNullOrEmpty(keyStr) && !string.IsNullOrEmpty(valueStr))
                            stringList.Add(keyStr, valueStr);
                    }
                }
            }
        }
    }
}
