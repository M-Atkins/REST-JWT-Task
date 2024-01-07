using System.ComponentModel.DataAnnotations;

public class User
{
    public string Name { get; set; }
    [Key]
    public string Email { get; set; }
    public string Password { get; set; }

}