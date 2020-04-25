// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Buffers.Text;
using System.Management.Automation.Language;
using System.Numerics;
using System.Security.Cryptography;
using Tpm2Lib;

namespace AttackSurfaceAnalyzer.Objects
{
    public abstract class CryptographicKeyObject : CollectObject
    {
        public string Source { get; set;  }

        public TpmAlgId tpmAlgId { get; set; } = TpmAlgId.Null;

        public override string Identity
        {
            get
            {
                return Source;
            }
        }
    }

    public class RSAKeyObject : CryptographicKeyObject
    {
        private RSA rsa;

        private bool ContainsPrivate = false;

        public RSAKeyObject(string Source, byte[] modulus, byte[] d, byte[]? p = null, byte[]? q = null)
        {
            this.Source = Source;
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

        public RSAKeyObject(string Source, string? PublicString = null, string? FullString = null)
        {
            this.Source = Source;
            rsa = RSA.Create();
            if (FullString != null)
            {
                rsa.ImportRSAPrivateKey(Convert.FromBase64String(FullString), out _);
            }
            else if (PublicString != null)
            {
                rsa.ImportRSAPublicKey(Convert.FromBase64String(PublicString), out _);
            }
        }

        public RSAKeyObject(string Source, string FullString)
        {
            this.Source = Source;
            rsa = RSA.Create();
        }

        public bool ShouldSerializePublicString()
        {
            return !ContainsPrivate;
        }

        public bool ShouldSerializeFullString()
        {
            return ContainsPrivate;
        }

        public string PublicString
        {
            get
            {
                
                return Convert.ToBase64String(rsa.ExportRSAPublicKey());
            }
        }

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
    }
}