// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Microsoft.CST.OAT;
using System.Collections.Generic;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    public class CompareResult
    {
        public CompareResult()
        {
        }

        public ANALYSIS_RESULT_TYPE Analysis { get; set; }

        public CollectObject? Base { get; set; }

        public string? BaseRunId { get; set; }

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

        public CollectObject? Compare { get; set; }

        public string? CompareRunId { get; set; }

        public List<Diff> Diffs { get; set; } = new List<Diff>();

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

        public List<Rule> Rules { get; set; } = new List<Rule>();
        public string AnalysesHash { get; set; } = string.Empty;

        public bool ShouldSerializeDiffs()
        {
            return Diffs?.Count > 0;
        }

        public bool ShouldSerializeRules()
        {
            return Rules?.Count > 0;
        }
    }
}