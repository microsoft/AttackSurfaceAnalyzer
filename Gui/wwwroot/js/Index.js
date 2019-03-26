$('#TelemetryOpt').change(function () {
    data = { 'DisableTelemetry': !$('#TelemetryOpt').is(":checked") };
    $.getJSON('Home/ChangeTelemetryState', data, function () { });
})