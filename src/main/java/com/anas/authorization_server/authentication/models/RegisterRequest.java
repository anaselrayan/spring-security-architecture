package com.anas.authorization_server.authentication.models;

public record RegisterRequest(String firstName, String lastName,
                              String email, String password, String passwordConfirm) {
}
