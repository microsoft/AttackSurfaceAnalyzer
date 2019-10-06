// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
namespace AttackSurfaceAnalyzer.Collectors
{
    public interface IPlatformRunnable
    {
        bool CanRunOnPlatform();
    }
}