package com.example.task4;

import com.example.task4.controllers.AuthController;
import com.example.task4.dto.AuthRequest;
import com.example.task4.dto.AuthResponse;
import com.example.task4.entities.User;
import com.example.task4.services.UserService;
import com.example.task4.security.JwtUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
public class AuthControllerTest {

    @InjectMocks
    private AuthController authController;

    @MockBean
    private UserService userService;

    @MockBean
    private JwtUtil jwtUtil;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @BeforeEach
    public void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(authController).build();
        objectMapper = new ObjectMapper();
    }

    @Test
    public void testLogin_Success() throws Exception {
        AuthRequest authRequest = new AuthRequest("user", "password");
        User user = new User();
        user.setUsername("user");
        user.setPassword("password");

        when(userService.findByUsername("user")).thenReturn(java.util.Optional.of(user));
        when(userService.checkPassword("password", "password")).thenReturn(true);
        when(jwtUtil.generateToken("user")).thenReturn("token");

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("token"));

        verify(userService).findByUsername("user");
        verify(userService).checkPassword("password", "password");
        verify(jwtUtil).generateToken("user");
    }

    @Test
    public void testLogin_UserNotFound() throws Exception {
        AuthRequest authRequest = new AuthRequest("user", "password");

        when(userService.findByUsername("user")).thenReturn(java.util.Optional.empty());

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authRequest)))
                .andExpect(status().isNotFound())
                .andExpect(content().string("User not found"));

        verify(userService).findByUsername("user");
        verifyNoMoreInteractions(userService);
        verifyNoInteractions(jwtUtil);
    }

    @Test
    public void testLogin_InvalidCredentials() throws Exception {
        AuthRequest authRequest = new AuthRequest("user", "password");
        User user = new User();
        user.setUsername("user");
        user.setPassword("password");

        when(userService.findByUsername("user")).thenReturn(java.util.Optional.of(user));
        when(userService.checkPassword("password", "password")).thenReturn(false);

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("Invalid credentials"));

        verify(userService).findByUsername("user");
        verify(userService).checkPassword("password", "password");
        verifyNoInteractions(jwtUtil);
    }

    @Test
    public void testRegister_Success() throws Exception {
        AuthRequest authRequest = new AuthRequest("user", "password");

        when(userService.findByUsername("user")).thenReturn(java.util.Optional.empty());

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authRequest)))
                .andExpect(status().isCreated())
                .andExpect(content().string("User registered successfully"));

        verify(userService).findByUsername("user");
        verify(userService).saveUser(any(User.class));
    }

    @Test
    public void testRegister_UserAlreadyExists() throws Exception {
        AuthRequest authRequest = new AuthRequest("user", "password");
        when(userService.findByUsername("user")).thenReturn(java.util.Optional.of(new User()));


        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authRequest)))
                .andExpect(status().isConflict())
                .andExpect(content().string("User already exists"));


        verify(userService).findByUsername("user");
        verify(userService, times(0)).saveUser(any(User.class)); // Ensure saveUser is not called
    }

}
