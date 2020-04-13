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
        private readonly byte[] _rowKey;
        private readonly byte[] _serialized;
        public byte[] GetRowKey() { return _rowKey; }
        public byte[] GetSerialized() { return _serialized; }

        public WriteObject(CollectObject ColObjIn, string RunIdIn)
        {
            ColObj = ColObjIn;
            RunId = RunIdIn;

            _serialized = JsonUtils.Dehydrate(ColObjIn);
            _rowKey = ColObj?.GetRowKey() ?? throw new ArgumentNullException(nameof(ColObjIn)); ;
        }

        public static WriteObject? FromBytes(byte[] SerializedIn, RESULT_TYPE ResultTypeIn, string RunIdIn)
        {
            var wo = new WriteObject(SerializedIn, ResultTypeIn, RunIdIn);
            if (wo.ColObj == null)
            {
                return null;
            }
            return wo;
        }

        private WriteObject(byte[] SerializedIn, RESULT_TYPE ResultTypeIn, string RunIdIn)
        {
            _serialized = SerializedIn;
            RunId = RunIdIn;            
            ColObj = JsonUtils.Hydrate(SerializedIn, ResultTypeIn) ?? throw new NullReferenceException(nameof(ColObj));
            _rowKey = ColObj.GetRowKey();
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var result = 0;
                foreach (byte b in _rowKey)
                    result = (result * 31) ^ b;
                return result;
            }
        }

        public override bool Equals(object? obj)
        {
            if (obj is WriteObject wo)
                return _rowKey.SequenceEqual(wo.GetRowKey());
            return false;
        }

        public bool Equals(WriteObject other)
        {
            return _rowKey.SequenceEqual(other.GetRowKey());
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

        public string InstanceHash
        {
            get
            {
                return Convert.ToBase64String(_rowKey);
            }
        }
    }
}
