package app.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Optional;

@Slf4j
@Configuration
// 인증 인가 활성화
@EnableWebSecurity
public class SecurityConfig {

    // TODO security 5 이상부터는 WebSecurityConfigurerAdapter 로 Setting 하지 않음

    /*
     * Spring 5
     * 1. WebSecurity
     *  WebSecurityCustomizer 빈등록을 통해 Spring Security 를 적용하지 않을 리소스를 설정
     *
     * 2. HttpSecurity
     *  SecurityFilterChain 빈등록을 통해 Spring Security 를 적용할 리소스를 설정
     **/

    /*
     * 1. 인증
     *  - http.formLogin()
     *  - http.logout()
     *
     * 2. 인가
     *  - http.authorizeRequests()
     *        .antMatchers("/admin")
     *        ...
     **/

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // 인증
                .authorizeRequests(req -> req
                        .anyRequest().authenticated()
                )
                // 인가 - FormLogin 인증 관련
                .formLogin(login -> login
//                                .loginPage("/loginPage")
                                .defaultSuccessUrl("/")
                                .failureUrl("/login")
                                .usernameParameter("userId")
                                .passwordParameter("passWd")
                                .loginProcessingUrl("/login-proc")
//                                .successHandler((request, response, authentication) -> {
//                                    System.out.println("authentication = " + authentication.getName());
//                                    response.sendRedirect("/");
//                                })
//                                .failureHandler((request, response, exception) -> {
//                                    log.error("login error", exception);
//                                    response.sendRedirect("/login");
//                                })
                                // 인증을 받지 않아도 접근이 가능해야함
                                .permitAll()
                )
                // 인가 - 로그아웃 method POST로 올라옴
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login")
                        // logout Cookie Delete
                        .deleteCookies("JSESSIONID", "remember-me")
                        // 기본 로그아웃 처리 외 추가 작업
                        .addLogoutHandler((request, response, authentication) -> {
//                            System.out.println("request = " + request.getSession());
                            HttpSession session = request.getSession(false);
                            Optional.ofNullable(session).ifPresent(HttpSession::invalidate);
                        })
                        // 로그아웃 성공 후
                        .logoutSuccessHandler((request, response, authentication) -> {
                            response.sendRedirect("/login");
                        })
                )

        ;
        return http.build();
    }

}
