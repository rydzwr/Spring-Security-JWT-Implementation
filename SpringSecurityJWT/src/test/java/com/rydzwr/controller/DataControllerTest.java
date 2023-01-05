package com.rydzwr.controller;

import jakarta.servlet.http.Cookie;
import org.json.JSONObject;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.rydzwr.constants.SecurityConstants;
import com.rydzwr.service.JWTService;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.springframework.boot.test.context.SpringBootTest;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.*;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.jupiter.api.Assertions.*;


@Slf4j
@SpringBootTest
@AutoConfigureMockMvc
public class DataControllerTest {
    static final String TOKEN_PREFIX = "Bearer ";
    static final String LOGIN_PREFIX = "Basic ";
    static final String HEADER_STRING = HttpHeaders.AUTHORIZATION;
    private MockMvc mockMvc;

    @Autowired
    private JWTService jwtService;

    @Autowired
    private WebApplicationContext context;

    @BeforeEach
    public void setup() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(springSecurity())
                .build();
    }

    private String generateAccessToken() {
        final Algorithm algorithm = Algorithm.HMAC256(SecurityConstants.JWT_KEY.getBytes());
        final Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        final String authorities = "authorities";
        final String test = "test";

        grantedAuthorities.add(new SimpleGrantedAuthority(test));

        return JWT.create()
                .withSubject(test)
                .withExpiresAt(new Date(System.currentTimeMillis() + 20 * 1000))
                .withIssuer(test)
                .withClaim(authorities, jwtService.populateAuthorities(grantedAuthorities))
                .sign(algorithm);
    }

    private HttpHeaders getInvalidAuthHeader() {
        HttpHeaders headers = new HttpHeaders();
        String accessToken = generateAccessToken();
        headers.add(HEADER_STRING, TOKEN_PREFIX + accessToken);
        return headers;
    }

    private HttpHeaders createBearerHeader(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(HEADER_STRING, TOKEN_PREFIX + token);
        return headers;
    }

    private HttpHeaders getBasicAuthHeader(String name, String password) {
        String valueToEncode = name + ":" + password;
        String encodedValue = Base64.getEncoder().encodeToString(valueToEncode.getBytes());

        HttpHeaders headers = new HttpHeaders();
        headers.add(HEADER_STRING,LOGIN_PREFIX + encodedValue);
        return headers;
    }

    @Test
    @DisplayName("Returns Forbidden When Request Called Without JWT Token (For Admin)")
    public void shouldReturnIsForbiddenForAdmin() throws Exception {
        this.mockMvc.perform(
                        get("/api/data/admin"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Returns Forbidden When Request Called Without JWT Token (For User)")
    public void shouldReturnIsForbiddenForUser() throws Exception {
        this.mockMvc.perform(
                        get("/api/data/user"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Returns Forbidden When Request Called With Invalid JWT Token (For Admin)")
    public void shouldReturnIsForbiddenForAdminRequestWithInvalidToken() throws Exception {
        this.mockMvc.perform(
                        get("/api/data/admin")
                                .headers(getInvalidAuthHeader()))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Returns Forbidden When Request Called With Invalid JWT Token (For User)")
    public void shouldReturnIsForbiddenForUserRequestWithInvalidToken() throws Exception {
        this.mockMvc.perform(
                        get("/api/data/user")
                                .headers(getInvalidAuthHeader()))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Should Login User And Return 200 Successful")
    public void shouldLoginUser() throws Exception {
        this.mockMvc.perform(
                        get("/api/login")
                                .servletPath("/api/login")
                                .headers(getBasicAuthHeader("user", "user123")))
                .andExpect(status().is2xxSuccessful());
    }

    @Test
    @DisplayName("Should Login Admin And Return 200 Successful")
    public void shouldLoginAdmin() throws Exception {
        this.mockMvc.perform(
                        get("/api/login")
                                .servletPath("/api/login")
                                .headers(getBasicAuthHeader("admin", "admin123")))
                .andExpect(status().is2xxSuccessful());
    }

    @Test
    @DisplayName("Should Not Authorize User To Enter Admin Page")
    public void shouldNotAuthorizeUserToEnterAdminPage() throws Exception {
        final String[] results = new String[2];
        this.mockMvc.perform(
                        get("/api/login")
                                .servletPath("/api/login")
                                .headers(getBasicAuthHeader("user", "user123")))
                .andDo(result -> {
            var parser = new JSONObject(result.getResponse().getContentAsString());
            results[0] = parser.getString("access_token");
            results[1] = parser.getString("role");
        });

        String accessToken = results[0];
        String userRole = results[1];

        assertNotNull(accessToken);
        assertThat(userRole, equalTo("USER"));

        this.mockMvc.perform(
                        get("/api/data/admin")
                                .headers(createBearerHeader(accessToken)))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Should Not Authorize Admin To Enter User Page")
    public void shouldNotAuthorizeAdminToEnterUserPage() throws Exception {
        final String[] results = new String[2];
        this.mockMvc.perform(
                        get("/api/login")
                                .servletPath("/api/login")
                                .headers(getBasicAuthHeader("admin", "admin123")))
                .andDo(result -> {
                    var parser = new JSONObject(result.getResponse().getContentAsString());
                    results[0] = parser.getString("access_token");
                    results[1] = parser.getString("role");
                });

        String accessToken = results[0];
        String userRole = results[1];

        assertNotNull(accessToken);
        assertThat(userRole, equalTo("ADMIN"));

        this.mockMvc.perform(
                        get("/api/data/user")
                                .headers(createBearerHeader(accessToken)))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Should Not Authorize User To See Secured Pages After Logout")
    public void shouldNotAuthorizeUserToSeeSecuredPagesAfterLogout() throws Exception {
        List<Cookie> cookies = new ArrayList<>();
        final String[] results = new String[2];

        // LOGGING USER && EXTRACTING RESPONSE DATA FOR FURTHER OPERATIONS
        this.mockMvc.perform(
                        get("/api/login")
                                .servletPath("/api/login")
                                .headers(getBasicAuthHeader("admin", "admin123")))
                .andDo(result -> {
                    var parser = new JSONObject(result.getResponse().getContentAsString());
                    cookies.addAll(Arrays.stream(result.getResponse().getCookies()).toList());
                    results[0] = parser.getString("access_token");
                    results[1] = parser.getString("role");
                });

        // SAVING USER'S ACCESS TOKEN AND ROLE FROM JSON
        String accessToken = results[0];
        String userRole = results[1];

        // SAVING REFRESH TOKEN FROM COOKIE
        Cookie refreshTokenCookie = cookies.stream()
                .filter((cookie) -> cookie.getName().equals("jwt"))
                .findAny()
                .get();

        String refreshTokenValue = refreshTokenCookie.getValue();

        // VALIDATING DATA
        assertNotNull(accessToken);
        assertThat(userRole, equalTo("ADMIN"));

        // EXPECTED RESPONSE FROM FURTHER REQUEST
        String expected = """
                {"data":"admin only data"}
                """;

        this.mockMvc.perform(
                        get("/api/data/admin")
                                .headers(createBearerHeader(accessToken)))
                .andDo(print()).andExpect(content().string(expected.trim()));


        // LOGGING OUT USER
        this.mockMvc.perform(
                        get("/api/logout")
                                .servletPath("/api/logout")
                                .headers(createBearerHeader(accessToken))
                                .cookie(new Cookie("jwt", refreshTokenValue)))
                .andExpect(status().is2xxSuccessful());


        // CHECKING THE SUCCESS OF PREVIOUS OPERATION
        this.mockMvc.perform(
                        get("/api/data/admin")
                                .headers(createBearerHeader(accessToken)))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Should Return New Access Token After Refresh Call")
    public void shouldReturnNewAccessTokenAfterRefreshCall() throws Exception {
        List<Cookie> cookies = new ArrayList<>();
        final String[] results = new String[2];
        final String[] refreshResults = new String[1];

        // LOGGING USER && EXTRACTING RESPONSE DATA FOR FURTHER OPERATIONS
        this.mockMvc.perform(
                        get("/api/login")
                                .servletPath("/api/login")
                                .headers(getBasicAuthHeader("admin", "admin123")))
                .andDo(result -> {
                    var parser = new JSONObject(result.getResponse().getContentAsString());
                    cookies.addAll(Arrays.stream(result.getResponse().getCookies()).toList());
                    results[0] = parser.getString("access_token");
                    results[1] = parser.getString("role");
                });

        // SAVING USER'S ACCESS TOKEN AND ROLE FROM JSON
        String accessToken = results[0];
        String userRole = results[1];

        // VALIDATING DATA
        assertNotNull(accessToken);
        assertThat(userRole, equalTo("ADMIN"));

        // SAVING REFRESH TOKEN FROM COOKIE
        Cookie refreshTokenCookie = cookies.stream()
                .filter((cookie) -> cookie.getName().equals("jwt"))
                .findAny()
                .get();

        String refreshTokenValue = refreshTokenCookie.getValue();

        // SENDING REQUEST FOR NEW ACCESS TOKEN
        this.mockMvc.perform(
                        get("/api/token/refresh")
                                .servletPath("/api/token/refresh")
                                .headers(createBearerHeader(accessToken))
                                .cookie(new Cookie("jwt", refreshTokenValue)))
                .andDo(result -> {
                    var parser = new JSONObject(result.getResponse().getContentAsString());
                    refreshResults[0] = parser.getString("access_token");
                });

        String newAccessToken = refreshResults[0];

        // ASSERTING RESULTS
        assertNotEquals(accessToken, newAccessToken);

        // CHECKING IS OLD TOKEN STILLS WORKS
        this.mockMvc.perform(
                        get("/api/data/admin")
                                .headers(createBearerHeader(accessToken)))
                .andExpect(status().isForbidden());

        // CHECKING NEW TOKEN
        this.mockMvc.perform(
                        get("/api/data/admin")
                                .headers(createBearerHeader(newAccessToken)))
                .andExpect(status().is2xxSuccessful());
    }

    @Test
    @DisplayName("Should Register New User And Then Allow Him to Login")
    public void registerTest() throws Exception {
        final String[] results = new String[2];

        // REGISTERING NEW USER TO DB
        this.mockMvc.perform(
                        get("/api/register")
                                .servletPath("/api/register")
                                .headers(getBasicAuthHeader("newUser", "newPass")))
                .andExpect(status().is(HttpStatus.CREATED.value()));

        // LOGGING AFTER SUCCESSFUL REGISTER
        this.mockMvc.perform(
                        get("/api/login")
                                .servletPath("/api/login")
                                .headers(getBasicAuthHeader("newUser", "newPass")))
                .andDo(result -> {
                    var parser = new JSONObject(result.getResponse().getContentAsString());
                    results[0] = parser.getString("access_token");
                    results[1] = parser.getString("role");
                });

        // SAVING USER'S ACCESS TOKEN AND ROLE FROM JSON
        String accessToken = results[0];
        String userRole = results[1];

        // VALIDATING DATA
        assertNotNull(accessToken);
        assertThat(userRole, equalTo("USER"));
    }

    @Test
    @DisplayName("Should Throw An Error When User Is Trying To Duplicate Username")
    public void checkDuplicateException() throws Exception {
        // REGISTERING NEW USER INTO DB
        this.mockMvc.perform(
                        get("/api/register")
                                .servletPath("/api/register")
                                .headers(getBasicAuthHeader("newUser", "newPass")))
                .andExpect(status().is(HttpStatus.CREATED.value()));

        // TRYING TO REGISTER USER WITH SAME USERNAME
        this.mockMvc.perform(
                        get("/api/register")
                                .servletPath("/api/register")
                                .headers(getBasicAuthHeader("newUser", "secondPass")))
                .andExpect(status().is(HttpStatus.CONFLICT.value()));
    }
}
