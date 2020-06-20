// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using System.Globalization;

namespace AttackSurfaceAnalyzer.Objects
{
    /// <summary>
    ///     Abstract parent class that all Collected data inherits from.
    /// </summary>
    public abstract class CollectObject
    {
        public abstract string Identity { get; }
        public RESULT_TYPE ResultType { get; set; }

        public string RowKey
        {
            get
            {
                return Serialized.GetHashCode().ToString(CultureInfo.InvariantCulture);
            }
        }

        public string Serialized
        {
            get
            {
                if (_serialized == null)
                {
                    _serialized = JsonUtils.Dehydrate(this);
                }

                return _serialized;
            }
        }

        public static bool ShouldSerializeRowKey()
        {
            return false;
        }

        public static bool ShouldSerializeSerialized()
        {
            return false;
        }

        private string? _serialized = null;
    }
}