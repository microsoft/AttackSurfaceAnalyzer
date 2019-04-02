// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System.Linq;
using System.Threading.Tasks;
using AttackSurfaceAnalyzer.Utils;
using ElectronNET.API;
using ElectronNET.API.Entities;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AttackSurfaceAnalyzer.Gui
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<CookiePolicyOptions>(options =>
            {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });


            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_1);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseCookiePolicy();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });

            BrowserWindowOptions browserWindowOptions = new BrowserWindowOptions();
            browserWindowOptions.Width = 1200;
            browserWindowOptions.Height = 842;
            browserWindowOptions.Resizable = true;
            browserWindowOptions.Center = true;
            browserWindowOptions.Title = "Attack Surface Analyzer Preview";
            browserWindowOptions.AutoHideMenuBar = true;

            DatabaseManager.Setup();

            string SELECT_TELEMETRY = "select value from persisted_settings where setting='telemetry_opt_out'";//lgtm [cs/literal-as-local]
            bool OptOut = false;

            using (var cmd = new SqliteCommand(SELECT_TELEMETRY, DatabaseManager.Connection, DatabaseManager.Transaction))
            {
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        OptOut = bool.Parse(reader["value"].ToString());
                    }
                }
            }

            TelemetryConfiguration.Active.DisableTelemetry = OptOut;

            Task.Run(async () =>
            {
                await Electron.WindowManager.CreateWindowAsync(browserWindowOptions);
            });
        }
    }
}