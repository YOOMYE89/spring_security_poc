package io.security.corespringsecurity.security.configs;

import io.security.corespringsecurity.security.common.FormWebAuthenticationDetailsSource;
import io.security.corespringsecurity.security.filter.AjaxLoginProcessingFilter;
import io.security.corespringsecurity.security.handler.FormAccessDeniedHandler;
import io.security.corespringsecurity.security.provider.FormAuthenticationProvider;
import io.security.corespringsecurity.security.service.UserDetailsServiceImpl;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class AppSecurityConfig {

    private final FormWebAuthenticationDetailsSource formWebAuthenticationDetailsSource;
    private final AuthenticationSuccessHandler formAuthenticationSuccessHandler;
    private final AuthenticationFailureHandler formAuthenticationFailureHandler;

    private final UserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity security) throws Exception {

        security
                .csrf().disable()
                .apply(new CustomDsl())
                .and()
                .authorizeRequests(request -> request
                        .antMatchers("/mypage").hasRole("USER")
                        .antMatchers("/messages").hasRole("MANAGER")
                        .antMatchers("/config").hasRole("ADMIN")
                        .antMatchers("/**").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(login -> login
                        .loginPage("/login")
                        .loginProcessingUrl("/login_proc")
                        .authenticationDetailsSource(formWebAuthenticationDetailsSource)
                        .successHandler(formAuthenticationSuccessHandler)
                        .failureHandler(formAuthenticationFailureHandler)
                        .permitAll()
                )
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                        .accessDeniedPage("/denied")
                        .accessDeniedHandler(accessDeniedHandler())
                )

        ;

        return security.build();
    }

    public class CustomDsl extends AbstractHttpConfigurer<CustomDsl, HttpSecurity> {
        @Override
        public void configure(HttpSecurity builder) throws Exception {

            AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);

            builder.addFilterBefore(new AjaxLoginProcessingFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class);
            builder.authenticationProvider(new FormAuthenticationProvider(userDetailsService, passwordEncoder()));
        }
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        FormAccessDeniedHandler commonAccessDeniedHandler = new FormAccessDeniedHandler();
        commonAccessDeniedHandler.setErrorPage("/denied");
        return commonAccessDeniedHandler;
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

}
