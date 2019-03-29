// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
$('#TelemetryOpt').change(function () {
    data = { 'DisableTelemetry': !$('#TelemetryOpt').is(":checked") };
    $.getJSON('Home/ChangeTelemetryState', data, function () { });
})