package app.domain.common;

import lombok.Getter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;

public class FormAuthenticationDetails extends WebAuthenticationDetails {

    @Getter
    private String secretKey;

    public FormAuthenticationDetails(HttpServletRequest request) {
        super(request);
        this.secretKey = request.getParameter("secretKey");
    }
}
