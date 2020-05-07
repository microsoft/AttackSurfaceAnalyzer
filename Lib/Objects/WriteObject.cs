// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using Serilog;
using System;

namespace AttackSurfaceAnalyzer.Objects
{
    public class WriteObject
    {
        public CollectObject ColObj { get; }
        public string RunId { get; }
        public string RowKey { get; }
        public string Serialized { get; }

        public WriteObject(CollectObject ColObjIn, string RunIdIn)
        {
            ColObj = ColObjIn ?? throw new ArgumentNullException(nameof(ColObjIn));
            RunId = RunIdIn;
            Serialized = JsonUtils.Dehydrate(ColObjIn);
            RowKey = ColObj.RowKey;
        }

        public static WriteObject? FromString(string SerializedIn, RESULT_TYPE ResultTypeIn, string RunIdIn)
        {
            var deserialized = JsonUtils.Hydrate(SerializedIn, ResultTypeIn);

            if (deserialized is CollectObject)
            {
                return new WriteObject(deserialized, RunIdIn);
            }
            else
            {
                Log.Debug($"Couldn't hydrate {SerializedIn} Failed to make a WriteObject.");
                return null;
            }
        }

        public string Identity
        {
            get
            {
                return ColObj?.Identity ?? string.Empty;
            }
        }
    }
}
