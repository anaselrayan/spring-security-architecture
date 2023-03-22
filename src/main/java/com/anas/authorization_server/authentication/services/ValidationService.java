package com.anas.authorization_server.authentication.services;

import com.anas.authorization_server.authentication.models.LoginRequest;
import com.anas.authorization_server.authentication.models.RegisterRequest;
import org.springframework.stereotype.Service;

import java.util.regex.Pattern;
/*
* THIS IS JUST FOR DEMO PURPOSES
* */
@Service
public class ValidationService {

    private final int EMAIL_MAX_LENGTH = 255;
    private final int PASSWORD_MAX_LENGTH = 16;
    private final int PASSWORD_MIN_LENGTH = 8;
    private final int NAME_MAX_LENGTH = 25;
    private final int NAME_MIN_LENGTH = 2;

    public boolean validRequest(LoginRequest request) {
        return validEmail(request.email())
                && validPassword(request.password());
    }

    public boolean validRequest(RegisterRequest request) {
        return validName(request.firstName())
                && validName(request.lastName())
                && validEmail(request.email())
                && validPasswords(request.password(), request.passwordConfirm());
    }

    public boolean validPasswords(String password, String confirm) {
        if (password == null || password.isEmpty()){
            return false;
        }
        boolean validLength = password.length() >= PASSWORD_MIN_LENGTH
                && password.length() <= PASSWORD_MAX_LENGTH;
        return password.equals(confirm) && validLength;
    }

    public boolean validEmail(String email) {
        if (email == null || email.isEmpty()){
            return false;
        }
        String EMAIL_REGEXP = "^[a-zA-Z0-9_!#$%&'*+/=?`{|}~^.-]+@[a-zA-Z0-9.-]+$";
        return Pattern.matches(EMAIL_REGEXP, email)
                && email.length() <= EMAIL_MAX_LENGTH;
    }

    public boolean validName(String name) {
        return name != null
                && name.length() >= NAME_MIN_LENGTH
                && name.length() <= NAME_MAX_LENGTH;
    }

    public boolean validPassword(String password) {
        return password != null
                && password.length() >= PASSWORD_MIN_LENGTH
                && password.length() <= PASSWORD_MAX_LENGTH;
    }
}
