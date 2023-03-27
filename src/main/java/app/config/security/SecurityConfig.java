package app.config.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Slf4j
@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity server) throws Exception {

        server
                // 인증 대상
                .authorizeRequests(request -> request
                        .antMatchers("/").permitAll()
                        .antMatchers("/mypage").hasRole("USER")
                        .antMatchers("/messages").hasRole("MANAGER")
                        .antMatchers("/config").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )

                // 인증 방식
                .formLogin()
        ;
        return server.build();
    }


    @Bean
    public WebSecurityCustomizer webSecurity() {
        return web -> web
                .ignoring()
                // 기본 정적 자원에 대한 ignore
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public UserDetailsService userDetailsService() {

        String password = passwordEncoder().encode("1111");
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

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
