using Business.Interfaces;
using Business.Models;
using Business.Validation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace UserManagementApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]

    public class UserController : ControllerBase
    {
        private readonly IIdentityService _identityService;

        public UserController(IIdentityService identityService)
        {
            _identityService = identityService;            
        }

        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] RegisterModel registerModel)
        {
            if (!ModelState.IsValid)
            {
                var errors = ModelState.Values.SelectMany(v => v.Errors.Select(e => e.ErrorMessage));
                return BadRequest(errors);
            }

            var registratioResult = await _identityService.RegisterUserAsync(registerModel);

            if (registratioResult != null && registratioResult.Success)
            {
                return Ok("User created.");
            }
            else if (registratioResult != null)
            {
                return BadRequest($"User could not be created. {registratioResult.ErrorMessage}");
            } 
            else
            {
                return BadRequest();
            }
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            if (!ModelState.IsValid)
            {
                var errors = ModelState.Values.SelectMany(v => v.Errors.Select(e => e.ErrorMessage));
                return BadRequest(errors);
            }

            var regisrationResult = await _identityService.LoginUserAsync(loginModel);

            if (regisrationResult != null)
            {

                return Ok(regisrationResult);
            }

            return BadRequest("Invalid login or password.");
        }

        [HttpPost("refresh-token")]
        [Authorize]
        public async Task<IActionResult> RefreshToken([FromBody] TokenRequestModel tokenRequestModel)
        {
            if (!ModelState.IsValid)
            {
                var errors = ModelState.Values.SelectMany(v => v.Errors.Select(e => e.ErrorMessage));
                return BadRequest(errors);
            }

            var result = await _identityService.VerifyAndGenerateTokenAsync(tokenRequestModel);

            return Ok(result);
        }

        [HttpPost("filtered-users")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> GetFilteredUsersAsync([FromBody] FilterUsersModel filters)
        {
            try
            {
                var filteredUsers = await _identityService.GetFilteredUsersAsync(filters);
                return Ok(filteredUsers);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        [HttpGet("details/{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> GetUserDetails(string id)
        {
            return Ok(await _identityService.GetUserDetailsByIdAsync(id));
        }

        [HttpPut("update/{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> UpdateUser([FromBody] RegisterModel registerModel, string id)
        {
            if (!ModelState.IsValid) 
            {
                var errors = ModelState.Values.SelectMany(v => v.Errors.Select(e => e.ErrorMessage));
                return BadRequest(errors);
            }

            try
            {
                await _identityService.UpdateUserAsync(registerModel, id);
                return Ok("User updated successfully.");
            }
            catch (UserManagerException ex)
            {
                if (ex.Message.Contains("not found"))
                {
                    return NotFound(ex.Message);
                }
                else
                {
                    return StatusCode(500, $"Internal server error. {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error. {ex.Message}");
            }
        }

        [HttpDelete("delete/{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<ActionResult> Delete(string id)
        {
            try
            {
                await _identityService.DeleteAsync(id);
                return Ok("User deleted successfully.");
            }
            catch (UserManagerException ex)
            {
                if (ex.Message.Contains("not found"))
                {
                    return NotFound(ex.Message);
                }
                else
                {
                    return StatusCode(500, $"Internal server error. {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error. {ex.Message}");
            }
        }

        [HttpPut("add-role/{id}")]
        [Authorize(Roles = "SuperAdmin")]
        public async Task<IActionResult> AddRoleToUser([FromBody] string role, string id)
        {
            if (!ModelState.IsValid)
            {
                var errors = ModelState.Values.SelectMany(v => v.Errors.Select(e => e.ErrorMessage));
                return BadRequest(errors);
            }

            try
            {
                await _identityService.AddRoleToUser(role, id);
                return Ok("Role added to user successfully.");
            }
            catch (UserManagerException ex)
            {
                if (ex.Message.Contains("not found"))
                {
                    return NotFound(ex.Message);
                }
                else
                {
                    return StatusCode(500, $"Internal server error. {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error. {ex.Message}");
            }
        }
    }
}
