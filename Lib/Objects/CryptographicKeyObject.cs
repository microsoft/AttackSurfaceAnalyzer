// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.

using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Newtonsoft.Json;
using Serilog;
using System;
using System.Security.Cryptography;
using MessagePack;
using Tpm2Lib;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [MessagePackObject]
    public class CryptographicKeyObject : CollectObject
    {
        public CryptographicKeyObject(string Source, TpmAlgId tpmAlgId)
        {
            this.Source = Source;
            this.tpmAlgId = tpmAlgId;
        }

        [IgnoreMember]
        public override RESULT_TYPE ResultType => RESULT_TYPE.KEY;

        [IgnoreMember]
        public override string Identity
        {
            get
            {
                return Source;
            }
        }

        [Key(2)]
        public RsaKeyDetails? RsaDetails { get; set; }
        [Key(0)]
        public string Source { get; set; }
        [Key(1)]
        public TpmAlgId tpmAlgId { get; set; } = TpmAlgId.Null;
    }

    public class KeyDetailObject
    {
    }

    [MessagePackObject]
    public class RsaKeyDetails : KeyDetailObject
    {
        public RsaKeyDetails(byte[] modulus, byte[] d, byte[]? p = null, byte[]? q = null)
        {
            var parameters = new RSAParameters()
            {
                D = d,
                Modulus = modulus
            };

            if (p != null && q != null)
            {
                parameters.P = p;
                parameters.Q = q;
                ContainsPrivate = true;
            }

            //parameters.InverseQ;
            //parameters.Exponent;
            //parameters.DP;
            //parameters.DQ;

            rsa = RSA.Create(parameters);
        }

        [SerializationConstructor]
        public RsaKeyDetails(string? PublicString = null, string? FullString = null)
        {
            rsa = RSA.Create();
            try
            {
                if (FullString != null)
                {
                    rsa.ImportRSAPrivateKey(Convert.FromBase64String(FullString), out _);
                }
                else if (PublicString != null)
                {
                    rsa.ImportRSAPublicKey(Convert.FromBase64String(PublicString), out _);
                }
            }
            catch(Exception e)
            {
                Log.Debug(e, "Failed to import RSA key.");
            }
        }

        [Key(1)]
        public string? FullString
        {
            get
            {
                if (ContainsPrivate)
                {
                    return Convert.ToBase64String(rsa.ExportRSAPrivateKey());
                }
                return null;
            }
        }

        [Key(0)]
        public string PublicString
        {
            get
            {
                return Convert.ToBase64String(rsa.ExportRSAPublicKey());
            }
        }

        public bool ShouldSerializeFullString()
        {
            return ContainsPrivate;
        }

        public bool ShouldSerializePublicString()
        {
            return !ContainsPrivate;
        }

        private bool ContainsPrivate = false;
        private RSA rsa;
    }
}