// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
"use strict";
$('#TelemetryOpt').change(function () {
    var data = { 'EnableTelemetry': $('#TelemetryOpt').is(":checked") };
    $.getJSON('Home/ChangeTelemetryState', data, function () { });
})