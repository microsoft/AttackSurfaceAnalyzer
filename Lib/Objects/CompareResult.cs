// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Microsoft.CST.OAT;
using System.Collections.Generic;
using MessagePack;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [MessagePackObject]
    public class CompareResult
    {
        public CompareResult()
        {
        }

        [Key(0)]
        public ANALYSIS_RESULT_TYPE Analysis { get; set; }

        [IgnoreMember]
        public CollectObject? Base { get; set; }

        [Key(1)]
        public string? BaseRunId { get; set; }

        [IgnoreMember]
        public CHANGE_TYPE ChangeType
        {
            get
            {
                if (Base != null)
                {
                    if (Compare != null)
                    {
                        return CHANGE_TYPE.MODIFIED;
                    }
                    else
                    {
                        return CHANGE_TYPE.DELETED;
                    }
                }
                else
                {
                    if (Compare != null)
                    {
                        return CHANGE_TYPE.CREATED;
                    }
                    else
                    {
                        return CHANGE_TYPE.INVALID;
                    }
                }
            }
        }

        [IgnoreMember]
        public CollectObject? Compare { get; set; }

        [Key(2)]
        public string? CompareRunId { get; set; }

        [Key(3)]
        public List<Diff> Diffs { get; set; } = new List<Diff>();

        [IgnoreMember]
        public string Identity
        {
            get
            {
                if (Base is CollectObject colObj)
                {
                    return colObj.Identity;
                }
                else if (Compare is CollectObject colObj2)
                {
                    return colObj2.Identity;
                }
                else
                {
                    return string.Empty;
                }
            }
        }

        [IgnoreMember]
        public RESULT_TYPE ResultType
        {
            get
            {
                if (Base is CollectObject colObj)
                {
                    return colObj.ResultType;
                }
                else if (Compare is CollectObject colObj2)
                {
                    return colObj2.ResultType;
                }
                else
                {
                    return RESULT_TYPE.UNKNOWN;
                }
            }
        }

        [Key(4)]
        public List<Rule> Rules { get; set; } = new List<Rule>();
        [Key(5)]
        public string AnalysesHash { get; set; } = string.Empty;

        [IgnoreMember]
        public int BaseRowId { get; set; } = -1;
        [IgnoreMember]
        public int CompareRowId { get; set; } = -1;
    }
}