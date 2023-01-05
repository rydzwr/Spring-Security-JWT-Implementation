package com.rydzwr.dto;

import com.rydzwr.validator.UniqueLogin;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AppUserDto {
    @UniqueLogin
    @Size(min = 3, max = 20)
    private String name;
    @Size(min = 3, max = 20)
    private String password;
    private String role;
}
