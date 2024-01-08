public class UserDTO 
{
    //DTO (Unused) to hide sensitive data from Unauthorized users (stretch)
    public string Email { get; set; }
    public string Name { get; set; }

    public UserDTO() {}
    public UserDTO(User UserItem) =>
    (Email, Name) = (UserItem.Email, UserItem.Name);
}