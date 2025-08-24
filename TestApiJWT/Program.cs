using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using TestApiJWT.Helpers;
using TestApiJWT.Models;
using TestApiJWT.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddOpenApi();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "My API", Version = "v1" });
});

//JWt Services and Settings

builder.Services.Configure<JWT>(builder.Configuration.GetSection("JWT"));
builder.Services.AddSingleton<JWT>();
//here we map it from settingsd into jwt class we made
//we but the scoped before database 
builder.Services.AddScoped<IAuthService, AuthService>();

//part of the Db and IdentityDb also 
builder.Services.AddIdentity<ApplicationUser, IdentityRole>().AddEntityFrameworkStores<ApplicationDbContext>();



builder.Services.AddDbContext<ApplicationDbContext>(
    o => o.
    UseSqlServer(builder.Configuration.GetConnectionString("MyConnection"
    )));


builder.Services.AddAuthentication(o =>
{
    o.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    o.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
    .AddJwtBearer(op =>
    {
        op.RequireHttpsMetadata = false;
        op.SaveToken = false;
        op.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateIssuerSigningKey = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidIssuer = builder.Configuration["JWT:Issuer"],
            ValidAudience = builder.Configuration["JWT:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Key"])),  

            // when the token expired the jwt give it more time before stop it 
            //it is a default time and if i want to stop it i  added this line
             ClockSkew = TimeSpan.Zero, 
             
        };
    });









var app = builder.Build();

// Configure pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "My .NET 9 API v1"));
    // app.MapOpenApi();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

// Add a test endpoint
app.MapGet("/", () => "Hello, World!");

app.Run();