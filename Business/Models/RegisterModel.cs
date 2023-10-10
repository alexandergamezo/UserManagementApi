using System.ComponentModel.DataAnnotations;

namespace Business.Models
{
    public class RegisterModel
    {
        public string Id { get; set; } = string.Empty;

        [Display(Name = "Name")]
        [Required(ErrorMessage = "Name is required")]
        public string? UserName { get; set; }

        [Required(ErrorMessage = "Age is required")]
        [Range(0, int.MaxValue, ErrorMessage = "Age must be a positive number")]
        public int Age { get; set; }

        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid Email Address")]
        public string? Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string? Password { get; set; }

        public ICollection<string>? Role { get; set; }
    }
}
