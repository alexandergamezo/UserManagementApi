using AutoMapper;
using Business.Interfaces;
using Business.Models;
using Business.Validation;
using Data.Entities;
using Data.Helpers;
using Data.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Business.Services
{
    public class IdentityService : IIdentityService
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IMapper _automapperProfile;
        private readonly IConfiguration _configuration;
        private readonly INLogger _logger;
        private readonly IUnitOfWork _unitOfWork;
        private readonly TokenValidationParameters _tokenValidationParameters;

        public IdentityService(UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager, IMapper automapperProfile, IConfiguration configuration, INLogger logger, IUnitOfWork unitOfWork, TokenValidationParameters tokenValidationParameters)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _automapperProfile = automapperProfile;
            _configuration = configuration;
            _logger = logger;
            _unitOfWork = unitOfWork;
            _tokenValidationParameters = tokenValidationParameters;
        }

        public async Task<RegisterResultModel?> RegisterUserAsync(RegisterModel registerModel)
        {
            AppUser? existingUser = null;

            if (registerModel.Email != null)
            {
                existingUser = await _userManager.FindByEmailAsync(registerModel.Email);
            }

            if (existingUser != null)
            {
                return new RegisterResultModel
                {
                    Success = false,
                    ErrorMessage = $"User {registerModel.Email} already exists."
                };
            }

            var newUser = _automapperProfile.Map<AppUser>(registerModel);

            IdentityResult? result = null;

            if(registerModel.Password != null)
            {
                result = await _userManager.CreateAsync(newUser, registerModel.Password);
            }                      

            if (result != null && result.Succeeded)
            {
                await _userManager.AddToRolesAsync(newUser, new List<string> { UserRoles.User });
                
                _logger.LogInformation("User registered successfully.");
                return new RegisterResultModel
                {
                    Success = true,
                    ErrorMessage = null
                };
            }
            else if (result != null)
            {
                _logger.LogError($"User registration failed: {string.Join(", ", result.Errors.Select(e => e.Description))}");
                return new RegisterResultModel
                {
                    Success = false,
                    ErrorMessage = (string?)string.Join(", ", result.Errors.Select(e => e.Description))
                };
            }

            _logger.LogError("Unexpected error occurred during user registration.");

            return null;
        }

        public async Task<AuthResultModel?> LoginUserAsync(LoginModel loginModel)
        {
            if (loginModel != null && loginModel.EmailAddress != null && loginModel.Password != null)
            {
                var existingUser = await _userManager.FindByEmailAsync(loginModel.EmailAddress);
                if (existingUser != null && await _userManager.CheckPasswordAsync(existingUser, loginModel.Password))
                {
                    var tokenValue = await GenerateJWTTokenAsync(existingUser, null, loginModel.RememberMe);

                    _logger.LogInformation("User logged in successfully.");
                    return tokenValue;
                }
            }

            _logger.LogError("User login failed: Invalid credentials or user not found.");

            return null;
        }

        private async Task<AuthResultModel> GenerateJWTTokenAsync(AppUser user, RefreshToken? rToken, bool rememberMe)
        {
            IList<Claim> authClaims = new List<Claim>();
            IList<string> userRoles = new List<string>();


            if (user != null && user.UserName != null && user.Email != null)
            {
                authClaims = new List<Claim>()
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(ClaimTypes.NameIdentifier, user.Id),
                    new Claim(JwtRegisteredClaimNames.Email, user.Email),
                    new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

                userRoles = await _userManager.GetRolesAsync(user);
            }


            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }


            string? secret = _configuration["JWT:Secret"];
            var authSigninKey = secret != null ? new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secret)) : null;

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:Issuer"],
                audience: _configuration["JWT:Audience"],
                expires: DateTime.UtcNow.AddMinutes(1),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigninKey, SecurityAlgorithms.HmacSha256));

            var jwtToken = new JwtSecurityTokenHandler().WriteToken(token);

            if (rToken != null)
            {
                var rTokenResponse = new AuthResultModel()
                {
                    Token = jwtToken,
                    RefreshToken = rToken.Token,
                    ExpiresAt = token.ValidTo
                };

                return rTokenResponse;
            }

            RefreshToken? refreshToken = null;
            if (rememberMe && user != null)
            {
                refreshToken = new RefreshToken()
                {
                    JwtId = token.Id,
                    IsRevoked = false,
                    UserId = user.Id,
                    DateAdded = DateTime.UtcNow,
                    DateExpire = DateTime.UtcNow.AddMonths(6),
                    Token = Guid.NewGuid().ToString() + "-" + Guid.NewGuid().ToString()
                };

                await _unitOfWork.RefreshTokensRepository.AddAsync(refreshToken);
                await _unitOfWork.SaveAsync();
            }

            var response = new AuthResultModel()
            {
                Token = jwtToken,
                RefreshToken = refreshToken == null ? string.Empty : refreshToken.Token,
                ExpiresAt = token.ValidTo
            };

            return response;
        }

        public async Task<AuthResultModel?> VerifyAndGenerateTokenAsync(TokenRequestModel tokenRequestModel)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var storedToken = (await _unitOfWork.RefreshTokensRepository.GetAllAsync()).FirstOrDefault(rt => rt.Token == tokenRequestModel.RefreshToken);

            AppUser? dbUser = null;
            if (storedToken != null && storedToken.UserId != null)
            {
                dbUser = await _userManager.FindByIdAsync(storedToken.UserId);
            }

            if (dbUser != null && storedToken != null)
            {
                try
                {
                    jwtTokenHandler.ValidateToken(tokenRequestModel.Token, _tokenValidationParameters, out var validatedToken);
                    return await GenerateJWTTokenAsync(dbUser, storedToken, true);
                }
                catch (SecurityTokenExpiredException)
                {
                    if (storedToken.DateExpire >= DateTime.UtcNow)
                    {
                        return await GenerateJWTTokenAsync(dbUser, storedToken, true);
                    }
                    else
                    {
                        return await GenerateJWTTokenAsync(dbUser, null, true);
                    }
                }
            }

            _logger.LogError("Unable to verify and generate token.");

            return null;
        }

        public async Task<IEnumerable<RegisterModel>> GetFilteredUsersAsync(FilterUsersModel filters)
        {
            var query = _userManager.Users;

            if (!string.IsNullOrEmpty(filters.Id))
                query = query.Where(u => u.Id == filters.Id);

            if (!string.IsNullOrEmpty(filters.Name) && filters.Name != null)
                query = query.Where(u => u.UserName != null && u.UserName.Contains(filters.Name));

            if (filters.Age.HasValue)
                query = query.Where(u => u.Age == filters.Age.Value);

            if (!string.IsNullOrEmpty(filters.Email))
                query = query.Where(u => u.Email != null && u.Email.Contains(filters.Email));

            if (!string.IsNullOrEmpty(filters.Role) && await _roleManager.RoleExistsAsync(filters.Role))
            {
                var usersInRole = await _userManager.GetUsersInRoleAsync(filters.Role);
                var userIdsInRole = usersInRole.Select(u => u.Id);
                query = query.Where(u => userIdsInRole.Contains(u.Id));
            }
            
            switch (filters.SortBy?.ToLower())
            {
                case "id":
                    query = filters.IsSortAscending ? query.OrderBy(u => u.Id) : query.OrderByDescending(u => u.Id);
                    break;
                case "name":
                    query = filters.IsSortAscending ? query.OrderBy(u => u.UserName) : query.OrderByDescending(u => u.UserName);
                    break;
                case "age":
                    query = filters.IsSortAscending ? query.OrderBy(u => u.Age) : query.OrderByDescending(u => u.Age);
                    break;
                case "email":
                    query = filters.IsSortAscending ? query.OrderBy(u => u.Email) : query.OrderByDescending(u => u.Email);
                    break;
                default:
                    break;
            }

            var pagedUsers = await query
                .Skip((filters.Page - 1) * filters.PageSize)
                .Take(filters.PageSize)
                .ToListAsync();

            var mappedUsers = pagedUsers.Select(user => _automapperProfile.Map<RegisterModel>(user));

            _logger.LogInformation($"Filtered users based on: {filters}");

            return mappedUsers;
        }

        public async Task<RegisterModel?> GetUserDetailsByIdAsync(string userId)
        {
            var existingUser = await _userManager.Users
                .SingleOrDefaultAsync(u => u.Id == userId);

            if (existingUser != null)
            {
                return _automapperProfile.Map<RegisterModel>(existingUser);
            }

            _logger.LogInformation($"User details requested for user with ID: {userId}");

            return null;
        }

        public async Task UpdateUserAsync(RegisterModel registerModel, string id)
        {
            ValidateModel(registerModel);
            var existingUser = await _userManager.FindByIdAsync(id);

            if (existingUser != null && registerModel.Password != null)
            {
                existingUser.UserName = registerModel.UserName;
                existingUser.Age = registerModel.Age;
                existingUser.Email = registerModel.Email;

                var newPasswordHash = _userManager.PasswordHasher.HashPassword(existingUser, registerModel.Password);
                existingUser.PasswordHash = newPasswordHash;

                var result = await _userManager.UpdateAsync(existingUser);

                if (result.Succeeded)
                {
                    _logger.LogInformation($"User updated successfully: {existingUser.UserName}");
                }
                else
                {
                    _logger.LogError($"Unable to update user: {string.Join(", ", result.Errors.Select(e => e.Description))}");
                    throw new UserManagerException($"Unable to update user: {string.Join(", ", result.Errors.Select(e => e.Description))}");
                }
            }
            else
            {
                _logger.LogError($"User with id '{id}' not found.");
                throw new UserManagerException($"User with id '{id}' not found.");
            }
        }

        public async Task DeleteAsync(string id)
        {
            var existingUser = await _userManager.FindByIdAsync(id);

            if (existingUser != null)
            {
                await _userManager.DeleteAsync(existingUser);

                _logger.LogInformation($"User deleted with ID: {id}");
            }
            else
            {
                _logger.LogError($"User with id '{id}' not found.");
                throw new UserManagerException($"User with id '{id}' not found.");
            }
        }

        public async Task AddRoleToUser(string role, string id)
        {
            var existingUser = await _userManager.FindByIdAsync(id);

            if (existingUser == null)
            {
                _logger.LogError($"User with id '{id}' not found.");
                throw new UserManagerException($"User with id '{id}' not found.");
            }

            var result = await _userManager.AddToRoleAsync(existingUser, role);

            if (!result.Succeeded)
            {
                _logger.LogError($"Unable to add role from user: {string.Join(", ", result.Errors.Select(e => e.Description))}");
                throw new UserManagerException($"Unable to add role from user: {string.Join(", ", result.Errors.Select(e => e.Description))}");
            }

            _logger.LogInformation($"Role '{role}' added to user with ID: {id}");
        }

        private static void ValidateModel(RegisterModel registerModel)
        {
            if (registerModel == null)
            {
                throw new UserManagerException("Game does not exist.");
            }

            if (registerModel.UserName == null)
            {
                throw new UserManagerException("Empty game name");
            }

            if (registerModel.Password == null)
            {
                throw new UserManagerException("Empty password");
            }
        }
    }
}
