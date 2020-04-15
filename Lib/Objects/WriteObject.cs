// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using System;
using System.Linq;

namespace AttackSurfaceAnalyzer.Objects
{
    public readonly struct WriteObject : IEquatable<WriteObject>
    {
        public readonly CollectObject ColObj { get; }
        public readonly string RunId { get; }
        public readonly string RowKey { get; }
        public readonly string Serialized { get; }

        public WriteObject(CollectObject ColObjIn, string RunIdIn)
        {
            ColObj = ColObjIn;
            RunId = RunIdIn;

            Serialized = JsonUtils.Dehydrate(ColObjIn);
            RowKey = ColObj?.RowKey ?? throw new ArgumentNullException(nameof(ColObjIn)); ;
        }

        public static WriteObject? FromString(string SerializedIn, RESULT_TYPE ResultTypeIn, string RunIdIn)
        {
            var wo = new WriteObject(SerializedIn, ResultTypeIn, RunIdIn);
            if (wo.ColObj == null)
            {
                return null;
            }
            return wo;
        }

        private WriteObject(string SerializedIn, RESULT_TYPE ResultTypeIn, string RunIdIn)
        {
            Serialized = SerializedIn;
            RunId = RunIdIn;
            ColObj = JsonUtils.Hydrate(SerializedIn, ResultTypeIn) ?? throw new NullReferenceException(nameof(ColObj));
            RowKey = ColObj.RowKey;
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var result = 0;
                foreach (byte b in RowKey)
                    result = (result * 31) ^ b;
                return result;
            }
        }

        public override bool Equals(object? obj)
        {
            if (obj is WriteObject wo)
                return RowKey.SequenceEqual(wo.RowKey);
            return false;
        }

        public bool Equals(WriteObject other)
        {
            return RowKey.SequenceEqual(other.RowKey);
        }

        public static bool operator ==(WriteObject left, WriteObject right)
        {
            return left.Equals(right);
        }

        public static bool operator !=(WriteObject left, WriteObject right)
        {
            return !(left == right);
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
