// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
namespace AttackSurfaceAnalyzer.Models
{
    public class ErrorViewModel
    {
        #region Public Properties

        public string? RequestId { get; set; }
        public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);

        #endregion Public Properties
    }
}