// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Resources;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Utils
{
    public static class Strings
    {
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
                using Stream? stream = typeof(FileSystemObject).Assembly.GetManifestResourceStream("AttackSurfaceAnalyzer.Properties.Resources.resources");
                if (stream is Stream)
                {
                    stringList.Clear();
                    using ResourceReader reader = new ResourceReader(stream);
                    foreach (DictionaryEntry? entry in reader)
                    {
                        if (entry is DictionaryEntry dictionaryEntry)
                        {
                            var keyStr = dictionaryEntry.Key.ToString();
                            var valueStr = dictionaryEntry.Value?.ToString();
                            if (!string.IsNullOrEmpty(keyStr) && !string.IsNullOrEmpty(valueStr))
                                stringList.TryAdd(keyStr, valueStr);
                        }
                    }
                }
            }
        }

        /// <summary>
        ///     Internal member structure holding string resources
        /// </summary>
        private static readonly Dictionary<string, string> stringList = new Dictionary<string, string>();
    }
}