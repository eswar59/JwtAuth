package com.vrv.assignment.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.validation.constraints.Size;
import org.hibernate.annotations.BatchSize;
import org.springframework.boot.autoconfigure.domain.EntityScan;

@Entity(name= "User_Details")
public class User {

    @Id
    @GeneratedValue
    private int id;

    @Size(min=3)
    private String username;

    @Size(min=3)
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String  password;

    @Size(min=3)
    private String roles;

    public User(int id, String username, String password, String roles) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.roles = roles;
    }

    public User(){}

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public @Size(min = 3) String getUsername() {
        return username;
    }

    public void setUsername(@Size(min = 3) String username) {
        this.username = username;
    }

    public @Size(min = 3) String getPassword() {
        return password;
    }

    public void setPassword(@Size(min = 3) String password) {
        this.password = password;
    }

    public @Size(min = 3) String getRoles() {
        return roles;
    }

    public void setRoles(@Size(min = 3) String roles) {
        this.roles = roles;
    }
}

