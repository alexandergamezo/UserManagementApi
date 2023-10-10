using System.ComponentModel.DataAnnotations;

namespace Business.Models
{
    public class TokenRequestModel
    {
        [Required]
        public string? Token { get; set; }

        public string? RefreshToken { get; set; }
    }
}
