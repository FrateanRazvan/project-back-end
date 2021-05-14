package ubb.postuniv.Project2021.user;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/users")
public class UserManagementController {

    private static final List<User> USERS = Arrays.asList(
            new User(1, "George"),
            new User(2, "Paul"),
            new User(3, "Ana")
    );

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINISTRATOR')")
    public List<User> getAllUsers(){
        return USERS;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('user: write')")
    public void registerNewUser(@RequestBody User user){
        System.out.println(user);
    }

    @DeleteMapping(path = "{userId}")
    @PreAuthorize("hasAuthority('user: write')")
    public void deleteUser(@PathVariable Integer userId){
        System.out.println(userId);
    }

    @PutMapping(path = "{userId}")
    @PreAuthorize("hasAuthority('user: write')")
    public void updateUser(@PathVariable Integer userId,@RequestBody User user){
        System.out.println(String.format("%s %s", userId, user));
    }
}
