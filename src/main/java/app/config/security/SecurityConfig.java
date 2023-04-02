package app.config.security;

import app.handler.CustomAccessDeniedHandler;
import app.handler.FailAuthenticationHandler;
import app.handler.SuccessAuthenticationHandler;
import app.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;

@Slf4j
@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

//    private final UserService userService;
    private final AuthenticationService authenticationService;
    private final PasswordEncoder encoder;
    private final AuthenticationDetailsSource authenticationDetailsSource;
    private final SuccessAuthenticationHandler successAuthenticationHandler;
    private final FailAuthenticationHandler failAuthenticationHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity server) throws Exception {

        server
                // UserDetailsService Custom 구현
//                .userDetailsService(userService)
                .authenticationProvider(authenticationService)
                // 인증 대상
                .authorizeRequests(request -> request
                        //
                        .antMatchers("/", "/users", "/login*").permitAll()
                        .antMatchers("/mypage").hasRole("USER")
                        .antMatchers("/messages").hasRole("MANAGER")
                        .antMatchers("/config").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )

                // 인증 방식
                .formLogin(login -> login
                        .loginPage("/login")
                        .defaultSuccessUrl("/")
                        .loginProcessingUrl("/login_proc")
                        .permitAll()
                        // 인증 정보 외 추가 정보 기입시
                        .authenticationDetailsSource(authenticationDetailsSource)
                        .successHandler(successAuthenticationHandler)
                        .failureHandler(failAuthenticationHandler)
                )
                .exceptionHandling(exception -> exception
                        .accessDeniedHandler(accessDeniedHandler())
                )

        ;

        return server.build();
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        CustomAccessDeniedHandler customAccessDeniedHandler = new CustomAccessDeniedHandler();
        customAccessDeniedHandler.setErrorPage("/denied");
        return customAccessDeniedHandler;
    }


    @Bean
    public WebSecurityCustomizer webSecurity() {
        return web -> web
                .ignoring()
                // 기본 정적 자원에 대한 ignore
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }


    /**
     * Memory 방식
     */
//    @Bean
    public UserDetailsService userDetailsService() {

        String password = encoder.encode("1111");
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();

        manager.createUser(
                User.withUsername("user")
                    .password(password)
                    .roles("USER")
                    .build()
        );

        manager.createUser(
                User.withUsername("manager")
                        .password(password)
                        // TODO 계층구조 설정
                        .roles("USER","MANAGER")
                        .build()
        );

        manager.createUser(
                User.withUsername("admin")
                        .password(password)
                        // TODO 계층구조 설정
                        .roles("USER","MANAGER","ADMIN")
                        .build()
        );

        return manager;
    }
}
