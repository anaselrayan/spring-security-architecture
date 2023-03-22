package com.anas.authorization_server.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;

@Entity
public class Address {
    @Id @GeneratedValue
    private int id;
    private String country;
    private String state;
    private String city;
    private String street;
}
