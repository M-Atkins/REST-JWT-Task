using System.ComponentModel.DataAnnotations;

public class User
{
    //User model requiring a Name, Email and Password
    public string Name { get; set; }
    [Key]
    public string Email { get; set; }
    public string Password { get; set; }

}