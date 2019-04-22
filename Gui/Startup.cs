// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Threading.Tasks;
using AttackSurfaceAnalyzer.Utils;
using ElectronNET.API;
using ElectronNET.API.Entities;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
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
            DatabaseManager.Setup();
            Logger.Setup();
            Telemetry.Setup(true);

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
            browserWindowOptions.Height = 1000;
            browserWindowOptions.Resizable = true;
            browserWindowOptions.Center = true;
            browserWindowOptions.Title = "Attack Surface Analyzer Preview";
#if DEBUG
            browserWindowOptions.AutoHideMenuBar = false;
#else
            browserWindowOptions.AutoHideMenuBar = true;
#endif

            Task.Run(async () =>
            {
                await Electron.WindowManager.CreateWindowAsync(browserWindowOptions);
            });
        }
    }
}