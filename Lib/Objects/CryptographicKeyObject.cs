// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Numerics;
using Tpm2Lib;

namespace AttackSurfaceAnalyzer.Objects
{
    public class CryptographicKeyObject : CollectObject
    {
        public string Source { get; set; }

        public object Public { get; set; }

        public object? Private { get; set; }

        public TpmAlgId tpmAlgId { get; set; } = TpmAlgId.Null;

        public CryptographicKeyObject(string Source, TpmAlgId tpmAlgId, object Public)
        {
            this.Source = Source;
            this.tpmAlgId = tpmAlgId;
            this.Public = Public;
            ResultType = Types.RESULT_TYPE.KEY;
        }

        public override string Identity
        {
            get
            {
                return Source;
            }
        }
    }

    public class RSAPublicInformation
    {
        public BigInteger modulus { get; set; }
        public BigInteger p { get; set; }
        public BigInteger q { get; set; }
    }

    public class RSAPrivateInformation
    {
        public BigInteger d { get; set; }
    }
}