package com.rydzwr.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@Table(name = "users", uniqueConstraints = { @UniqueConstraint(name = "name", columnNames = "name") })
@NoArgsConstructor
public class AppUser {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private int id;
    @Size(min = 3, max = 20)
    private String name;
    @Size(min = 3, max = 200)
    private String password;
    private String role;
    private String refreshToken;

    public AppUser(String name, String password, String role, String refreshToken) {
        this.name = name;
        this.password = password;
        this.role = role;
        this.refreshToken = refreshToken;
    }
}
