using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using RefreshToken.Auth;
using RefreshToken.Services;
using UserServer.Utils;

namespace RefreshToken.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly IJwtTokenService _jwtTokenService;

        public AuthenticateController(IUserService userService, IJwtTokenService jwtTokenService)
        {
            _userService = userService;
            _jwtTokenService = jwtTokenService;
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            try
            {
                var response = await _userService.LoginUser(model);
                return Ok(response);
            }
            catch (CustomErrorHandling ex)
            {
                return StatusCode((int)ex.StatusCode, new Response { Status = "Error", Message = ex.Message });
            }
            catch (Exception ex)
            {
                return BadRequest(new Response { Status = "Error", Message = ex.Message });
            }
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            try
            {
                var response = await _userService.RegisterUser(model);
                return Ok(new Response { Status = "Success", Message = "User created successfully!" });
            }
            catch(CustomErrorHandling ex)
            {
                return StatusCode((int)ex.StatusCode, new Response{Status = "Error", Message = ex.Message });
            }
            catch (Exception ex)
            {
                return BadRequest(new Response { Status = "Error", Message = ex.Message });
            }
        }

        [HttpPost]
        [Route("register-admin")]
        public async Task<IActionResult> RegisterAdmin([FromBody] RegisterModel model)
        {
            try
            {
                var response = await _userService.RegisterAdmin(model);
                return Ok(new Response { Status = "Success", Message = "Admin Created Successfully" });
            }
            catch (CustomErrorHandling ex)
            {
                return StatusCode((int)ex.StatusCode, new Response { Status = "Error", Message = ex.Message });
            }
            catch (Exception ex)
            {
                return BadRequest(new Response { Status = "Error", Message = ex.Message });
            }
        }

        [HttpPost]
        [Route("refresh-token")]
        public async Task<IActionResult> RefreshToken(TokenModel tokenModel)
        {
            try
            {
                var response = await _jwtTokenService.RefreshToken(tokenModel);
                return Ok(response.Value);
            }
            catch (CustomErrorHandling ex)
            {
                return StatusCode((int)ex.StatusCode, new Response { Status = "Error", Message = ex.Message });
            }
            catch (Exception ex)
            {
                return BadRequest(new Response { Status = "Error", Message = ex.Message });
            }
        }

        [Authorize]
        [HttpPost]
        [Route("revoke/{username}")]
        public async Task<IActionResult> Revoke(string username)
        {
            try
            {
                string response = await _userService.RevokeUser(username);
                return NoContent();
            }
            catch (CustomErrorHandling ex)
            {
                return StatusCode((int)ex.StatusCode, new Response { Status = "Error", Message = ex.Message });
            }
            catch (Exception ex)
            {
                return BadRequest(new Response { Status = "Error", Message = ex.Message });
            }
        }

        [Authorize(Roles = UserRoles.Admin)]
        [HttpPost]
        [Route("revoke-all")]
        public async Task<IActionResult> RevokeAll()
        {
            try
            {
                var response = await _userService.RevokeAllUsers();
                return NoContent();
            }
            catch (CustomErrorHandling ex)
            {
                return StatusCode((int)ex.StatusCode, new Response { Status = "Error", Message = ex.Message });
            }
            catch (Exception ex)
            {
                return BadRequest(new Response { Status = "Error", Message = ex.Message });
            }
        }
    }
}
