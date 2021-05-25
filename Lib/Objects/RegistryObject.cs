// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    public class RegistryObject : CollectObject
    {
        public RegistryObject(string Key, RegistryView View)
        {
            ResultType = RESULT_TYPE.REGISTRY;
            this.View = View;
            this.Key = Key;
        }

        public override string Identity
        {
            get
            {
                return $"{View}_{Key}";
            }
        }

        /// <summary>
        ///     The Full Path to the Key in the Registry
        /// </summary>
        public string Key { get; set; }

        public Dictionary<string, List<string>> Permissions { get; set; } = new Dictionary<string, List<string>>();
        public string? PermissionsString { get; set; }

        public int SubkeyCount
        {
            get { return Subkeys?.Count ?? 0; }
        }

        public List<string>? Subkeys { get; set; }

        public int ValueCount
        {
            get { return Values?.Count ?? 0; }
        }

        public Dictionary<string, string>? Values { get; set; }
        public RegistryView View { get; private set; }

        public static Dictionary<string, string> GetValues(RegistryKey key)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }
            Dictionary<string, string> values = new Dictionary<string, string>();

            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return values;
            }
            // Write values under key and commit
            foreach (var value in key.GetValueNames())
            {
                RegistryValueKind rvk = key.GetValueKind(value);
                string str;

                switch (rvk)
                {
                    case RegistryValueKind.MultiString:
                        str = string.Join(Environment.NewLine, (string[]?)key.GetValue(value) ?? new string[] { });
                        break;

                    case RegistryValueKind.Binary:
                        str = Convert.ToBase64String((byte[]?)key.GetValue(value) ?? new byte[] { });
                        break;

                    case RegistryValueKind.ExpandString:
                    case RegistryValueKind.String:
                        str = (string?)key.GetValue(value) ?? string.Empty;
                        break;

                    case RegistryValueKind.DWord:
                    case RegistryValueKind.QWord:
                    default:
                        str = key.GetValue(value)?.ToString() ?? string.Empty;
                        break;
                }
                values.Add(value, str);
            }
            return values;
        }

        public void AddSubKeys(string[] subkeysIn)
        {
            if (Subkeys == null)
            {
                Subkeys = new List<string>();
            }
            Subkeys.AddRange(subkeysIn);
        }
    }
}