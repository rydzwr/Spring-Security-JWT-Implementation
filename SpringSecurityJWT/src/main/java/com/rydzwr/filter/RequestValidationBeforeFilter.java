package com.rydzwr.filter;

import com.rydzwr.service.AuthHeaderDataExtractor;
import jakarta.servlet.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class RequestValidationBeforeFilter implements Filter {

    private final AuthHeaderDataExtractor extractor;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        extractor.extract(request);
        chain.doFilter(request, response);
    }

}