using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using TestApiJWT.Helpers;
using TestApiJWT.Models;

namespace TestApiJWT.Services
{
    public interface IAuthService
    {
        Task<AuthModel> RegisterAsync(RegisterModel model);
        Task<AuthModel> GetTokenAsync(TokenRequestModel model);
        Task<string> AddRolesAsync(AddRoleModel model);
    }




    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly JWT _jwt;

        public AuthService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, JWT jwt)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _jwt = jwt;
        }


        #region       Register
        public async Task<AuthModel> RegisterAsync(RegisterModel model)
        {
            // 1 -  check if the email exist or not 
            var existemail = await _userManager.FindByEmailAsync(model.Email);
            if (existemail is not null)
            {
                return new AuthModel { Message = $"Email {model.Email} is already exist" };
            }
            var existname = await _userManager.FindByNameAsync(model.UserName);
            if (existname is not null)
            {
                return new AuthModel { Message = $"UserName {model.UserName} is already exist" };
            }

            var user = new ApplicationUser
            {
                UserName = model.UserName,
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName,
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                var errors = string.Empty;
                foreach (var error in result.Errors)
                {
                    errors += $"{error.Description} ,";
                }

                return new AuthModel { Message = errors };
            }

            await _userManager.AddToRoleAsync(user, "User");

            var jwtSecurity = await CreateJWTToken(user);

            return new AuthModel
            {
                Email = user.Email,
                //ExpiresIn = jwtSecurity.ValidTo,
                IsAuthenticated = true,
                Roles = new List<string> { "User" },
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurity),
                UserName = user.UserName,
            };
        }

        private async Task<JwtSecurityToken> CreateJWTToken(ApplicationUser user)
        {
            // Retrieve existing claims for the user
            var userClaims = _userManager.GetClaimsAsync(user).Result;

            // Retrieve roles assigned to the user
            var roles = _userManager.GetRolesAsync(user).Result;

            // Convert roles into claims
            var roleClaims = new List<Claim>();
            foreach (var role in roles)
            {
                roleClaims.Add(new Claim("roles", role)); // You could use ClaimTypes.Role here
            }

            // Core claims for the token
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),          // Subject: username
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // Unique token ID
                new Claim(JwtRegisteredClaimNames.Email, user.Email),           // Email
                new Claim("uid", user.Id)                                       // Custom user ID claim
            }
            .Union(userClaims)   // Merge with existing user claims
            .Union(roleClaims);  // Merge with role claims

            // Create the symmetric key from the secret
            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));

            // Define signing credentials using HMAC SHA256
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            // Build the JWT token
            var token = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: DateTime.Now.AddDays(_jwt.DeurationInDays),
                signingCredentials: signingCredentials
            );

            return token; // Return the token object
        }
        #endregion


        #region        GetTokenAsync &&   AddRolesAsync
        public async Task<AuthModel> GetTokenAsync(TokenRequestModel model)
        {

            var authModel = new AuthModel();
            var user = await _userManager.FindByEmailAsync(model.Email);

            if (user == null)
            {
                authModel.Message = "Email is Incorrect";
                return authModel;
            }

            var result = await _userManager.CheckPasswordAsync(user, model.Password);
            if (!result)
            {
                authModel.Message = "Password is Incorrect!";
                return authModel;
            }




            var jwtSecurity = await CreateJWTToken(user);
            var roleList = await _userManager.GetRolesAsync(user);


            authModel.IsAuthenticated = true;
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurity);
            authModel.Email = user.Email;
            authModel.UserName = user.UserName;
            //  authModel.ExpiresIn = jwtSecurity.ValidTo;
            authModel.Roles = roleList.ToList();


            //we check if the user has any active refresh token or not 
            if (user.RefreshTokens.Any(t => t.IsActive))
            {
                var activeRefreshToken = user.RefreshTokens.First(t => t.IsActive);
                authModel.RefreshToken = activeRefreshToken.Token;
                authModel.RefreshTokenExpiration = activeRefreshToken.EpiresOn;
            }

            else
            {
                var refreshToken = GenerateRefreshToken();
                authModel.RefreshToken = refreshToken.Token;
                authModel.RefreshTokenExpiration = refreshToken.EpiresOn;
                user.RefreshTokens.Add(refreshToken);

                await _userManager.UpdateAsync(user);
            }



                return authModel;

        }

        public async Task<string> AddRolesAsync(AddRoleModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null)
            {
                return "Invaild User Id";
            }

            var roelexist = await _roleManager.RoleExistsAsync(model.Role);

            if (!roelexist)
            {
                return "Invaild Role";
            }

            var userRole = await _userManager.IsInRoleAsync(user, model.Role);

            if (userRole)
                return "User Has tis Role already";


            var result = await _userManager.AddToRoleAsync(user, model.Role);

            return result.Succeeded ? string.Empty : "Something went wrong";


        }
        #endregion 


        private RefreshToken GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            //Old way to generate random number 
            // using var generator = new RNGCryptoServiceProvider();
            // generator.GetBytes(randomNumber);

            // this is new way
            RandomNumberGenerator.Fill(randomNumber);
            return new RefreshToken
            {
                Token = Convert.ToBase64String(randomNumber),
                EpiresOn = DateTime.UtcNow.AddDays(10),
                CreatedOn = DateTime.UtcNow
            };

        }








    }
}
