using Microsoft.EntityFrameworkCore;

class UserDb : DbContext
{
    public UserDb(DbContextOptions<UserDb> options)
        : base(options) { }
    //Map User objs to DB using DBSet
    public DbSet<User> Users => Set<User>();
}