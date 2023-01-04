﻿// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Serilog;
using System;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    public class WriteObject
    {
        public WriteObject(CollectObject ColObjIn, string RunIdIn)
        {
            ColObj = ColObjIn ?? throw new ArgumentNullException(nameof(ColObjIn));
            RunId = RunIdIn;
            Serialized = ColObj.Serialized;
            RowKey = ColObj.RowKey;
        }

        public CollectObject ColObj { get; }

        public string Identity
        {
            get
            {
                return ColObj?.Identity ?? string.Empty;
            }
        }

        public string RowKey { get; }
        public string RunId { get; }
        public byte[] Serialized { get; }

        public static WriteObject? FromBytes(byte[] SerializedIn, RESULT_TYPE ResultTypeIn, string RunIdIn)
        {
            var deserialized = SerializationUtils.Hydrate(SerializedIn, ResultTypeIn);

            if (deserialized is not null)
            {
                return new WriteObject(deserialized, RunIdIn);
            }

            Log.Debug($"Couldn't hydrate {SerializedIn} Failed to make a WriteObject.");
            return null;
        }
    }
}