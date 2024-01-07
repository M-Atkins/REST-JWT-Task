public class UserDTO 
{
    public string Email { get; set; }
    public string Password { get; set; }

    public UserDTO() {}
    public UserDTO(User UserItem) =>
    (Email, Password) = (UserItem.Email, UserItem.Password);
}