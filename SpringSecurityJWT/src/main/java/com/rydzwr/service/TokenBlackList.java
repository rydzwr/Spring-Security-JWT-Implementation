package com.rydzwr.service;

import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

@Component
public class TokenBlackList {
    private static Set<String> list = new HashSet<>();

    public boolean contains(String token) {
        return list.contains(token);
    }

    public void add(String token) {
        list.add(token);
    }

}
