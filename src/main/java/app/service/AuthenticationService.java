package app.service;

import app.domain.context.UserContext;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;


@Component
@RequiredArgsConstructor
public class AuthenticationService implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;

    private final PasswordEncoder encoder;

    // 검증을 위한
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String username = authentication.getName();
        String password = (String) authentication.getCredentials();

        UserContext context = (UserContext) userDetailsService.loadUserByUsername(username);

        // password validate
        if (!encoder.matches(password, context.getPassword())) {
            throw new BadCredentialsException("Password is not matched");
        }

        // 인증 후 인증정보 전달
        return new UsernamePasswordAuthenticationToken(context.getAccount(), null, context.getAuthorities());
    }

    // 인증 객체에 대한 동작 validate
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
