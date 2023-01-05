package com.rydzwr.validator;

import com.rydzwr.repository.AppUserRepository;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
class UniqueLoginValidator implements ConstraintValidator<UniqueLogin, String> {
    private final AppUserRepository userRepository;

    public boolean isValid(String login, ConstraintValidatorContext context) {
        return login != null && !userRepository.existsByName(login);
    }
}
