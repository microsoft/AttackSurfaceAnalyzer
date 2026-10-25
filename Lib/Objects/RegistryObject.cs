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
            this.View = View;
            this.Key = Key;
        }

        public override RESULT_TYPE ResultType => RESULT_TYPE.REGISTRY;

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

        /// <summary>
        ///     The key's security descriptor in SDDL form.
        /// </summary>
        /// <remarks>
        ///     A flat string, so analysis rules can match ACE patterns against it with Regex. The
        ///     Permissions dictionary cannot be matched that way: OAT's regex operation discards the
        ///     dictionary half of a field's values.
        /// </remarks>
        public string? PermissionsString { get; set; }

        /// <summary>
        ///     CLSID-shaped GUIDs referenced by this key's values, in braced uppercase form.
        /// </summary>
        /// <remarks>
        ///     Pre-parsed at collection time because analysis rules cannot follow a reference from one
        ///     object to another. A List&lt;string&gt; so that Regex, Contains, StartsWith, and EndsWith all
        ///     work against it.
        /// </remarks>
        public List<string> ReferencedClsids { get; set; } = new List<string>();

        /// <summary>
        ///     File paths referenced by this key's values, environment-expanded and normalized.
        /// </summary>
        public List<string> ReferencedPaths { get; set; } = new List<string>();

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
            Dictionary<string, string> values = new();

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