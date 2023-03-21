package app.controller.page;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Slf4j
@Controller
@RequestMapping("/page")
public class PageController {

    @GetMapping("/loginPage")
    public String login() {
        return "login";
    }
}
