using IdentityServer.CustomError;
using IdentityServer.Services;
using IdentityServer.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityServer.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        private readonly IUserService _userService;

        public AuthenticateController(IUserService userService)
        {
            _userService = userService;
        }

        [HttpPost]
        [Route("register")]
        public IActionResult Register(RegisterModel model)
        {
            try
            {
                string response = _userService.RegisterUser(model);
                return StatusCode(201, new Response { Status = "Success", Message = response });
            }
            catch(CustomErrorHandling ex)
            {
                return StatusCode((int)ex.StatusCode, new Response { Status = "Error", Message = ex.Message});
            }
            catch (Exception ex)
            {
                return BadRequest(new Response { Status = "Error", Message = ex.Message });
            }
        }

        [HttpPost]
        [Route("login")]
        public IActionResult Login(LoginModel model)
        {
            try
            {
                ObjectResult response = _userService.LoginUser(model);
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

        [HttpPost]
        [Route("refresh-token")]
        public IActionResult RefreshToken(TokenModel token)
        {
            try
            {
                ObjectResult response = _userService.RefreshAccessToken(token);
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
        public IActionResult Revoke(string username)
        {
            try
            {
                string response = _userService.RevokeUser(username);
                return Ok(new Response { Status = "Success", Message = response });
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

        [Authorize(Roles = "ADMIN")]
        [HttpPost]
        [Route("revoke-all")]
        public IActionResult RevokeAll()
        {
            try
            {
                string response = _userService.RevokeAllUsers();
                return Ok(new Response { Status = "Success", Message = response });
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
