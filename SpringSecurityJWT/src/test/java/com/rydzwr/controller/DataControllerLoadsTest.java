package com.rydzwr.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
public class DataControllerLoadsTest {

    @Autowired
    private DataController dataController;

    @Test
    public void contextLoads() {
        assertThat(dataController).isNotNull();
    }
}
