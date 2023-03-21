package app.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.time.Duration;
import java.util.UUID;

@Controller
public class SecurityController {

    private final String ACCESS_TOKEN = "ACT";

    @GetMapping("/")
    @ResponseBody
    public String index() {
        return "home";
    }
    @GetMapping("/home")
    public String home(HttpServletResponse res) {

        String s = UUID.randomUUID().toString();



//        res.addHeader("Set-Cookie", ACCESS_TOKEN + "=" + s +";Secure;SameSite=None");
//
//        System.out.println(" home ");

        ResponseCookie cookie = ResponseCookie.from(ACCESS_TOKEN, s)
                .path("/")
                .domain(".shinhancard.com")
                .httpOnly(true)
//                .maxAge(Duration.ofHours(1))
                .secure(true)
                .sameSite("None")
                .build();

        res.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        return "login";
    }

    @GetMapping("/user")
    public String user() {
        return "user";
    }

    @GetMapping("/admin/pay")
    public String adminPay() {
        return "adminPay";
    }

    @GetMapping("/admin/**")
    public String adminAll() {
        return "system";
    }
}
