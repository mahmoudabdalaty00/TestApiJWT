using System.ComponentModel.DataAnnotations;

namespace TestApiJWT.Models
{
    public class AddRoleModel
    {
        [MaxLength(100), Required]
        public string UserId { get; set; }
        [MaxLength(100), Required]
        public string Role { get; set; }
    }

}
