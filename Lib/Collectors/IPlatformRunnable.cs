// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
namespace Microsoft.CST.AttackSurfaceAnalyzer.Collectors
{
    public interface IPlatformRunnable
    {
        bool CanRunOnPlatform();
    }
}