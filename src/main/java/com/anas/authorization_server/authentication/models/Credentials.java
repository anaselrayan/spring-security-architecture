package com.anas.authorization_server.authentication.models;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@AllArgsConstructor
@Setter @Getter
public class Credentials {
    private String email;
    private String password;
}
