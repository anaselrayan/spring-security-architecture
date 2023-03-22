# spring-security-architecture
Custom implementation for Spring Security Authorization Server that have two authentication providers 

![Spring Security Architecture](https://backendstory.com/content/images/size/w1000/2022/02/7.-Scenario-5.1---Multiple-Custom-AuthenticationProvider-1.png)

### There are many security filters and authentication providers implemented by Spring Team,
### I tried to re-implemenet two main filters (Basic & JWT) to understand how things work internally.

## End points:

* /auth
  + /login [POST]: accept username & password and return accessToken & refreshToken
  + /register [POST]: accept registerRequest and return accessToken & refreshToken

* /token
  + /exchange [POST]: accept refreshToken and return accessToken
  + /refresh_valid [POST]: accept refreshToken and returns 'True' if it's valid
  + /access_valid [POST]: accept accessToken and returns 'True' if it's valid

* /demo [GET]: test endpoint that returns 'Demo' for only authenticated users

## Authentication Providers:

* Jwt Authentication Provider: create and validate jwt tokens
* Basic Authentication Provider: validate the Base64 encoded username:password

## Security Filters:

* Jwt Authorization Filter: filters incomming requests that have Authorization header whith keyword 'Bearer ' 
* Basic Authorization Filter: filters incomming requests that have Authorization header with keyword 'Basic '
