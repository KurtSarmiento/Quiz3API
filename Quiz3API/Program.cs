using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

var jwtKey = "9f3a7c2e5b1d8a4f6c0e92b7d5a3f8c1";

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false;
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
        NameClaimType = ClaimTypes.Name,
        RoleClaimType = ClaimTypes.Role
    };
});

builder.Services.AddRateLimiter(options =>
{
    options.OnRejected = async (context, token) =>
    {
        var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
        logger.LogWarning("Rate limit exceeded for IP {IP}", context.HttpContext.Connection.RemoteIpAddress);

        context.HttpContext.Response.StatusCode = 429;
        await context.HttpContext.Response.WriteAsync("Too many requests!", token);
    };
    options.AddPolicy("LoginPolicy", context =>
    {
        var role = context.User?.FindFirst(ClaimTypes.Role)?.Value;

        int limit = role switch
        {
            "Admin" => 5, //5 login requests for admin
            _ => 3 //3 login requests for everyone else
        };

        var apiKey = context.Request.Headers["X-API-Key"].ToString();
        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: apiKey ?? "anonymous",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = limit,
                QueueLimit = 0,
                Window = TimeSpan.FromMinutes(1)
            });
    });
    options.AddPolicy("TasksPolicy", context =>
    {
        var role = context.User?.FindFirst(ClaimTypes.Role)?.Value;

        int limit = role switch
        {
            "Admin" => 30, //30 requests for admin
            _ => 10 //10 requests for everyone else
        };

        var apiKey = context.Request.Headers["X-API-Key"].ToString();
        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: apiKey ?? "anonymous",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = limit,
                QueueLimit = 0,
                Window = TimeSpan.FromMinutes(1)
            });
    });
});

builder.Services.AddAuthorization();
// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

//app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

app.UseRateLimiter();

app.MapControllers();

app.Run();
