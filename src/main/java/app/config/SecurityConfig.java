package app.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.servlet.http.HttpSession;
import javax.sql.DataSource;
import java.util.Optional;

@Slf4j
@Configuration
// 인증 인가 활성화
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserDetailsService userDetailsService;

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
                // 인가 API
                /*
                 * 1. 선언적 방식
                 *  - URL ex) http.antMatchers("/user/**").hasRole("USER")
                 *  - Method
                 *    ex) @PreAuthorize("hasRole('USER')")
                 *        public void user() {...}
                 * 2. 동적 방식
                 *  - URL
                 *  - Method
                 */

                // 경로 설정을 먼저하면 해당 경로에 대해서만
//                .antMatcher("/shop")
                // 위에서 부터 아래로 진행됨 - 구체적인 경로가 먼저오고 포함 경로가 나중에
                .authorizeRequests(req -> req
                        .antMatchers("/user").hasRole("USER")
                        .antMatchers("/admin/pay").hasRole("ADMIN")
                        .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                        // 해당 경로에 대해서는 모든 권한을 줌
//                        .antMatchers("/shop/login", "/shop/users/**").permitAll()
//                        // 해당 경로에 대해서는 USER 역할 여부
//                        .antMatchers("/shop/mypage").hasRole("USER")
//                        // 표현식을 통한 역할 통제 RBAC
//                        .antMatchers("/shop/admin/pay").access("hasRole('ADMIN') or hasRole('SYS')")
                        // 그 외 요청은 모두 권한이 필요함
                        .anyRequest().authenticated()
                )
                // 인가 - FormLogin 인증 관련
                .formLogin(login -> login
//                                .loginPage("/page/loginPage")
                                .usernameParameter("userId")
                                .passwordParameter("passWd")
                                .loginProcessingUrl("/login-proc")
                                .defaultSuccessUrl("/home")
                                .failureUrl("/login")
//                                .successHandler((request, response, authentication) -> {
//                                    System.out.println("authentication = " + authentication.getName());
//                                    response.sendRedirect("/home");
//                                })
//                                .failureHandler((request, response, exception) -> {
//                                    log.error("login error", exception);
//                                    response.sendRedirect("/page/loginPage");
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

                // refresh 기능
                .rememberMe(remember -> remember
                        .rememberMeParameter("remember")
                        // 만료쿠키 시간 3600 초 1 시간
                        .tokenValiditySeconds(3600)
                        // 항상 remember 처리됨
                        .alwaysRemember(false)
                        // 시스템 사용자 계정 처리
                        .userDetailsService(userDetailsService)
                )
                // 세션 관리 기능
                .sessionManagement(session -> session
                        // 최대 세션 허용 개수
                        .maximumSessions(1)
                        // default false : 기존 로그인 만료 cf) true : 기존 로그인 차단
                        .maxSessionsPreventsLogin(false)
                        // 세션 만료시
//                        .expiredUrl("/login")
                        .and()
                        // 세션이 유효하지 않을때 -> 설정된 경우 만료시에도 적용됨.
                        .invalidSessionUrl("/login")
                        .sessionFixation()
                                // 기본값 - 세션 고정 보호
                                .changeSessionId()
//                              .none()
                        /**
                         * 1. SessionCreationPolicy.ALWAYS - 스프링 시큐리티가 세션 항상 생성
                         * 2. SessionCreationPolicy.IF_REQUIRED - 스프링 시큐리티가 세션 필요 시 생성
                         * 3. SessionCreationPolicy.NEVER - 스프링 시큐리티가 세션 생성하지 않음 이미 존재하면 사
                         * 4. SessionCreationPolicy.STATELESS - 스프링 시큐리티가 생성하지도 않고 존재해도 사용하지 않음
                         */
                        .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
                )

        ;
        return http.build();
    }


    @Bean
    public DataSource dataSource() {
        return new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();
    }
    // user 생성
    @Bean
    public InMemoryUserDetailsManager users(DataSource dataSource) {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("1111")
                .roles("USER")
                .build();

        UserDetails sys = User.withDefaultPasswordEncoder()
                .username("sys")
                .password("1111")
                // TODO 권한 계층 구조를 통해서 처리해야함
                .roles("SYS", "USER")
                .build();

        UserDetails admin = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("1111")
                // TODO 권한 계층 구조를 통해서 처리해야함
                .roles("ADMIN","SYS","USER")
                .build();

        return new InMemoryUserDetailsManager(user, sys, admin);
    }

}
