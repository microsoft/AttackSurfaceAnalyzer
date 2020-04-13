// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;

namespace AttackSurfaceAnalyzer.Objects
{
    /// <summary>
    /// Abstract parent class that all Collected data inherits from.
    /// </summary>
    public abstract class CollectObject
    {
        public RESULT_TYPE ResultType { get; set; }
        public abstract string Identity { get; }

        private byte[] RowKey
        {
            get
            {
                return CryptoHelpers.CreateHash(JsonUtils.Dehydrate(this));
            }
        }

        public byte[] GetRowKey()
        {
            return RowKey;
        }
    }
}
