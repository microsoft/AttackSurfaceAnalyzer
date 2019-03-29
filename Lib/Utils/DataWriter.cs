// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
namespace AttackSurfaceAnalyzer.Utils
{
    class DataWriter
    {
        public static void Write(object o)
        {
            Logger.Instance.Error("Received Object {0}", o);
        }
    }
}