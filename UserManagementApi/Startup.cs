using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Data.Entities;
using Data.Data;
using Business;
using Microsoft.EntityFrameworkCore;
using Data.Interfaces;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.OpenApi.Models;
using Business.Interfaces;
using Business.Services;
using Business.Logger;

namespace UserManagementApi
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            var configurationBuilder = new ConfigurationBuilder();
            configurationBuilder.SetBasePath(Path.Combine(Directory.GetCurrentDirectory(), "../"));
            configurationBuilder.AddJsonFile("Data/appsettings.json", optional: false, reloadOnChange: true);
            var configuration = configurationBuilder.Build();

            services.AddSingleton<IConfiguration>(configuration);
            services.AddSingleton<INLogger, NLogger>();


            services.AddDbContext<UserManagementDbContext>(options =>
                options.UseSqlServer(configuration.GetConnectionString("DefaultConnection")));
            
            services.AddAutoMapper(cfg =>
            {
                cfg.AddProfile(new AutomapperProfile(
                    services.BuildServiceProvider().GetRequiredService<UserManager<AppUser>>()));
            });

            services.AddTransient<IUnitOfWork, UnitOfWork>();
            services.AddTransient<IIdentityService, IdentityService>();
            services.AddTransient<IHttpContextAccessor, HttpContextAccessor>();

            string? secret = configuration["JWT:Secret"];
            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(secret != null ? Encoding.ASCII.GetBytes(secret) : null),

                ValidateIssuer = true,
                ValidIssuer = configuration["JWT:Issuer"],

                ValidateAudience = true,
                ValidAudience = configuration["JWT:Audience"],

                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            services.AddSingleton(tokenValidationParameters);

            services.AddIdentity<AppUser, IdentityRole>()
                .AddEntityFrameworkStores<UserManagementDbContext>()
                .AddDefaultTokenProviders()
                .AddSignInManager<SignInManager<AppUser>>();

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            })
                .AddJwtBearer(options =>
                {
                    options.SaveToken = true;
                    options.RequireHttpsMetadata = false;
                    options.TokenValidationParameters = tokenValidationParameters;
                });

            services.AddControllers();
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "UserManagementApi", Version = "v1" });
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();

                app.UseSwagger();
                app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "UserManagementApi v1"));
            }

            app.UseHttpsRedirection();
            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
            
            AppDbInitializer.SeedRolesToDb(app).Wait();
        }
    }
}
