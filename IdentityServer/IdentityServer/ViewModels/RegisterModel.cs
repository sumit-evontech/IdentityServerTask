using System.ComponentModel.DataAnnotations;

namespace IdentityServer.ViewModels
{
    public class RegisterModel
    {
        [Required(ErrorMessage = "User Name is required")]
        public string Username { get; set; } = string.Empty;

        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email address format")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Password is required")]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{8,}$",
        ErrorMessage = "Password must contain at least 1 uppercase letter, 1 digit, 1 special character, and be at least 8 characters long")]
        public string Password { get; set; } = string.Empty;

        public string Role { get; set; } = "USER";
    }
}
