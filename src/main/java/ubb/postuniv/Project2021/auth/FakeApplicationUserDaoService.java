package ubb.postuniv.Project2021.auth;

import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static ubb.postuniv.Project2021.security.AplicationUserRole.*;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao{

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers().stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers(){
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
            new ApplicationUser(USER.getGrantedAuthorities(),
                    passwordEncoder.encode("password"),
                    "user",
                    true,
                    true,
                    true,
                    true
            ),
             new ApplicationUser(ADMIN.getGrantedAuthorities(),
                    passwordEncoder.encode("password123"),
                    "admin",
                    true,
                    true,
                    true,
                    true
            ),
             new ApplicationUser(ADMINISTRATOR.getGrantedAuthorities(),
                    passwordEncoder.encode("password123"),
                    "administrator",
                    true,
                    true,
                    true,
                    true
            )

        );

        return applicationUsers;
    }
}
