package com.rydzwr.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@Table(name = "users")
@NoArgsConstructor
public class AppUser {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private int id;
    private String name;
    private String password;
    private String role;

    public AppUser(String name, String password, String role) {
        this.name = name;
        this.password = password;
        this.role = role;
    }
}
