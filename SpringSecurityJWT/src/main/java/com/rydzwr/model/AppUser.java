package com.rydzwr.model;

import jakarta.persistence.*;
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
    private String name;
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
