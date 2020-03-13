using AttackSurfaceAnalyzer.Utils;
using System;
using System.Linq;

namespace AttackSurfaceAnalyzer.Objects
{
    public readonly struct WriteObject : IEquatable<WriteObject>
    {
        public CollectObject ColObj { get; }
        public string RunId { get; }
        private readonly byte[] _rowKey;
        private readonly byte[] _serialized;
        public byte[] GetRowKey() { return _rowKey; }
        public byte[] GetSerialized() { return _serialized; }

        public WriteObject(CollectObject ColObj, string RunId)
        {
            if (ColObj == null)
            {
                throw new ArgumentNullException(nameof(ColObj));
            }
            this.ColObj = ColObj;
            this.RunId = RunId;

            _serialized = JsonUtils.Dehydrate(ColObj);
            _rowKey = CryptoHelpers.CreateHash(_serialized);
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
                return ColObj.Identity;
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
