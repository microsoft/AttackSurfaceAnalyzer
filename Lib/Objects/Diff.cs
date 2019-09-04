using System;
using System.Collections.Generic;
using System.Text;

namespace AttackSurfaceAnalyzer.Objects
{
    public class Diff
    {
        public string Field { get; set; }
    }

    class AddDiff : Diff
    {
        public object Added { get; set; }
    }

    class RemoveDiff : Diff
    {
        public object Removed { get; set; }
    }
    class ModifiedDiff : Diff
    {
        public ModifiedDiff(string name, object before, object after)
        {
            Field = name;
            Before = before;
            After = after;

        }
        public object Before { get; set; }
        public object After { get; set; }
    }
}
