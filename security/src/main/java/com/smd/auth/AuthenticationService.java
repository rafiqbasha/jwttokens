package com.smd.auth;

import com.smd.config.JwtService;
import com.smd.user.Role;
import com.smd.user.User;
import com.smd.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationService.class);

    public AuthenticationResponse register(RegisterRequest request) {

        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
            userRepository.save(user);
            var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse
                .builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticationResponse registerSuperAdmin(RegisterRequest request) {
        if (userRepository.findByRole(Role.SUPER_ADMIN).isPresent()) {
            throw new IllegalStateException("Super admin already exists");
        }
        logger.info("Registering super admin: " + request.getEmail());
        var superAdmin = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.SUPER_ADMIN)
                .build();
        userRepository.save(superAdmin);
        var jwtToken = jwtService.generateToken(superAdmin);
        return AuthenticationResponse.builder().token(jwtToken).build();
    }

    public AuthenticationResponse authenticate(AuthenticateRequest request) {
        try {
            logger.info("Authenticating user: " + request.getEmail());
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );

            var user = userRepository.findByEmail(request.getEmail())
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));

            var jwtToken = jwtService.generateToken(user);
            logger.info("Authentication successful for user: " + request.getEmail());
            return AuthenticationResponse.builder().token(jwtToken).build();
        } catch (Exception e) {
            logger.error("Authentication failed for user: " + request.getEmail(), e);
            throw new RuntimeException("Invalid credentials");
        }
    }
}
