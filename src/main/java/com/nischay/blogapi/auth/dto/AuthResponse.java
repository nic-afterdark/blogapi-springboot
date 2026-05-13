package com.nischay.blogapi.auth.dto;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AuthResponse {
    private  Long userId;
    private String username;
    private String email;
    private String message;
}
