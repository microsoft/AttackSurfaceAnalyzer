// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;

namespace AttackSurfaceAnalyzer.Objects
{
    /// <summary>
    /// Abstract parent class that all Collected data inherits from.
    /// </summary>
    public abstract class CollectObject
    {
        #region Public Properties

        public abstract string Identity { get; }
        public RESULT_TYPE ResultType { get; set; }

        public string RowKey
        {
            get
            {
                return CryptoHelpers.CreateHash(JsonUtils.Dehydrate(this));
            }
        }

        #endregion Public Properties

        #region Public Methods

        public static bool ShouldSerializeRowKey()
        {
            return false;
        }

        #endregion Public Methods
    }
}