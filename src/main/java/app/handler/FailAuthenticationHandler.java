package app.handler;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class FailAuthenticationHandler extends SimpleUrlAuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//        super.onAuthenticationFailure(request, response, exception);
        String errorMsg = "Invalid username or password";

        if (exception instanceof BadCredentialsException) {
            errorMsg = "Invalid username or password";
        } else if (exception instanceof InsufficientAuthenticationException) {
            errorMsg = "Invalid SecretKey";
        } else {
            errorMsg = "Fucking error";
        }

        // 스프링 시큐리티는 /~ 모두를 URL로 인식함 이에 예외처리해야함
        setDefaultFailureUrl("/login?error=true&errorMsg=" + errorMsg);

        super.onAuthenticationFailure(request, response, exception);
    }
}
