using API.DTOs;
using API.Services;
using Domain;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<User> _userManager;
        private readonly TokenService _tokenService;

        public AccountController(UserManager<User> userManager, TokenService tokenService)
        {
            _userManager = userManager;
            _tokenService = tokenService;
        }

        [AllowAnonymous] // 不需要驗證
        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
        {
            var user = await _userManager.FindByEmailAsync(loginDto.Email);

            if (user == null)
                return Unauthorized();

            var result = await _userManager.CheckPasswordAsync(user, loginDto.Password);

            if (result)
            {
                return CreateUserObject(user);
            }

            return Unauthorized();
        }

        [AllowAnonymous] // 不需要驗證
        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
        {
            var existsUserName = await _userManager.Users.AnyAsync(
                x => x.UserName == registerDto.Username
            );

            if (existsUserName)
                return BadRequest("Username is already taken");

            var existsEmail = await _userManager.Users.AnyAsync(x => x.Email == registerDto.Email);

            if (existsEmail)
                return BadRequest("Email is already taken");

            var user = new User
            {
                DisplayName = registerDto.DisplayName,
                Email = registerDto.Email,
                UserName = registerDto.Username
            };

            var result = await _userManager.CreateAsync(user, registerDto.Password);

            if (result.Succeeded)
            {
                return CreateUserObject(user);
            }

            return BadRequest(result.Errors);
        }

        [Authorize]
        [HttpGet("me")]
        public async Task<ActionResult<UserDto>> GetCurrentUser()
        {
            var user = await _userManager.FindByIdAsync(
                User.FindFirstValue(ClaimTypes.NameIdentifier)
            );

            return CreateUserObject(user);
        }

        private UserDto CreateUserObject(User user)
        {
            return new UserDto
            {
                DisplayName = user.DisplayName,
                Image = null,
                Token = _tokenService.CreateToken(user),
                Username = user.UserName
            };
        }
    }
}
