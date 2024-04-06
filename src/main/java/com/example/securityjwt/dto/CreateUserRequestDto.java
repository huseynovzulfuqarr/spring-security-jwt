package com.example.securityjwt.dto;

import com.example.securityjwt.model.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class CreateUserRequestDto {
    private String name;
    private String username;
    private String password;
    private Set<Role> authorities;
}
