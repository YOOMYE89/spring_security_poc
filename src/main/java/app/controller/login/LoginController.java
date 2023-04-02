package app.controller.login;

import app.domain.entity.Account;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.thymeleaf.model.IModel;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller
public class LoginController {

    @GetMapping("/login")
    public String login(
            @RequestParam(value = "error", required = false) String error,
            @RequestParam(value = "errorMsg", required = false) String errorMsg,
            Model model
    ) {

        System.out.println("error = " + error);
        System.out.println("error = " + errorMsg);

        model.addAttribute("error", error);
        model.addAttribute("errorMsg", errorMsg);

        return "user/login/login";
    }

    @GetMapping("/logout")
    public String logout(HttpServletRequest req, HttpServletResponse res) {

        // 인증객체
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null) {
            new SecurityContextLogoutHandler().logout(req, res, authentication);
        }

        return "redirect:/";
    }

    @GetMapping("/denied")
    public String accessDenied(
            @RequestParam(value = "errorMsg", required = false) String errorMsg,
            Model model
    ) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Account account = (Account) authentication.getPrincipal();

        model.addAttribute("username", account.getUsername());
        model.addAttribute("errorMsg", errorMsg);

        return "user/login/denied";
    }
}
