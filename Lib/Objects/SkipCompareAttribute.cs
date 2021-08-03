using System;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [AttributeUsage(AttributeTargets.All)
]
    public class SkipCompareAttribute : Attribute
    {
        public SkipCompareAttribute()
        {
        }
    }
}
