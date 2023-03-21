package app.service;

import app.domain.dto.UserDto;
import app.domain.entity.Account;

import java.util.List;

public interface UserService {
    List<Account> getUsers();
    UserDto getUser(Long id);
    void createUser(Account account);
    void deleteUser(Long idx);
}
