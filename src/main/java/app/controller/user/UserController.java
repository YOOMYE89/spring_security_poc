package app.controller.user;

import app.domain.dto.AccountDto;
import app.domain.entity.Account;
import app.service.UserService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final PasswordEncoder encoder;

    @GetMapping(value="/mypage")
    public String myPage() throws Exception {
        return "user/mypage";
    }

    @GetMapping("/users")
    public String createUser() {
        return "user/login/register";
    }

    /**
     * user create
     */
    @PostMapping("/users")
    public String createUser(AccountDto accountDto) {

        ModelMapper modelMapper = new ModelMapper();
        // 깊은 복사
        Account account = modelMapper.map(accountDto, Account.class);
        account.setPassword(encoder.encode(account.getPassword()));
        userService.createUser(account);

        return "redirect:/";
    }
}
