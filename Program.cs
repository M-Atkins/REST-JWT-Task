
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDbContext<UserDb>( opt => opt.UseInMemoryDatabase("Users"));

//Logs
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

builder.Services.AddAuthentication(options =>
    {
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(o =>
{
    o.TokenValidationParameters = new TokenValidationParameters
    {
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey
        (Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"])),
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = false,
        ValidateIssuerSigningKey = true
    };
});

//Authorization, add Admin role and Policy.
builder.Services.AddAuthorization();

var app = builder.Build();

//endpoints
var Users = app.MapGroup("/users");
var Jwt = app.MapGroup("/jwt");

//GET All Users Requires JWT Auth
Users.MapGet("/", GetAllUsers)
    .RequireAuthorization();

//Require No Auth, just for testing Db
Users.MapGet("/user/", GetUser);
Users.MapPost("/", CreateUser);
Users.MapPut("/", UpdateUser);
Users.MapDelete("/", DeleteUser);

Jwt.MapPost("/generateToken", GenerateToken);

app.Run();

async Task<IResult> GenerateToken(string email, string password, UserDb db)
{
    //Lookup
    var check = await db.Users.FindAsync(email);

    if (await db.Users.FindAsync(email) is User user && check.Password == password) 
    {
        var issuer = builder.Configuration["Jwt:Issuer"];
        var audience = builder.Configuration["Jwt:Audience"];
        var key = Encoding.ASCII.GetBytes
        (builder.Configuration["Jwt:Key"]);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim("Id", Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti,
                Guid.NewGuid().ToString())
            }),
            Expires = DateTime.UtcNow.AddMinutes(5),
            Issuer = issuer,
            Audience = audience,
            SigningCredentials = new SigningCredentials
            (new SymmetricSecurityKey(key),
            SecurityAlgorithms.HmacSha512Signature)
        };
        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        var jwtToken = tokenHandler.WriteToken(token);
        var stringToken = tokenHandler.WriteToken(token);
        return Results.Ok(stringToken);
    }
    return Results.Unauthorized();
}

static async Task<IResult> GetAllUsers(UserDb db)
{
    return TypedResults.Ok(await db.Users.ToArrayAsync());
}

//Get single User
static async Task<IResult> GetUser(string email, UserDb db)
{
    //Get users by primary key and check if exists
    return await db.Users.FindAsync(email)
        is User user 
            ? TypedResults.Ok(user)
            : TypedResults.NotFound();
}

static async Task<IResult> CreateUser(User user, UserDb db)
{
    db.Users.Add(user);
    await db.SaveChangesAsync();

    return TypedResults.Created($"/users/{user.Email}", user);
}

//PUT requests to change properties of Users
static async Task<IResult> UpdateUser(string email, User inputField, UserDb db)
{
    var user = await db.Users.FindAsync(email);

    if (user is null) return TypedResults.NotFound();

    //Reassign with args
    user.Name = inputField.Name;
    user.Email = inputField.Email;
    user.Password = inputField.Password;

    await db.SaveChangesAsync();

    //Return 204 no content
    return TypedResults.NoContent();
}

//Remove User by key (email) and save
static async Task<IResult> DeleteUser(string email, UserDb db)
{
    if (await db.Users.FindAsync(email) is User user)
    {
        db.Users.Remove(user);
        await db.SaveChangesAsync();
        return TypedResults.NoContent();
    }
    //if not found return 404
    return TypedResults.NotFound();
}