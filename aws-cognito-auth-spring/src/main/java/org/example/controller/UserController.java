package org.example.controller;

import com.amazonaws.services.cognitoidp.model.SignUpResult;
import com.amazonaws.services.cognitoidp.model.UserType;
import org.example.model.UserLoginRequestPayload;
import org.example.model.UserLoginResponsePayload;
import org.example.model.UserRegisterConfirmRequest;
import org.example.model.UserRegisterRequest;
import org.example.service.contract.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/user")
public class UserController {

    private UserService userService;

    @Autowired
    public UserController(UserService userService){
        this.userService = userService;
    }
    @GetMapping
    public String hello() {
        return "hello";
    }
    @PostMapping
    public ResponseEntity<String> create(@RequestBody UserRegisterRequest user) {
        UserType result = null;

        try{
            result = userService.signUp(user.getName(), user.getName(), user.getEmail(), user.getPassword());

            if(result != null)
                return new ResponseEntity<>("User successfully created", HttpStatus.CREATED);
            else
                return new ResponseEntity<>("Error to create user", HttpStatus.BAD_REQUEST);

        }catch (Exception ex){
            return new ResponseEntity<>("Error to create user", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PutMapping(value="/{userName}/confirm")
    public ResponseEntity<String> confirm(@PathVariable String userName, @RequestBody String code){
        try{
            userService.confirmSignUp(code, userName);

            return new ResponseEntity<>("User confirmed", HttpStatus.OK);

        }catch (Exception ex){
            return new ResponseEntity<>("Error to confirm user", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping(value="/sigIn")
    public ResponseEntity<?> login(@RequestBody UserLoginRequestPayload user) {
        try{
            var result = userService.signIn(user.getUserName(), user.getPassword());

            if(result != null){
                UserLoginResponsePayload userLoginResponsepayload = new UserLoginResponsePayload();
                userLoginResponsepayload.setAccessToken(result.get("accessToken"));
                userLoginResponsepayload.setRefreshToken(result.get("refreshToken"));

                return ResponseEntity.ok(userLoginResponsepayload);
            }else{
                return new ResponseEntity<>("Error to auth user", HttpStatus.UNAUTHORIZED);
            }

        }catch (Exception ex){
            //log the error
            return new ResponseEntity<>("Error to auth user", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping(value="/auth")
    public ResponseEntity<?> auth(@RequestHeader("Authorization") String token) {
        try {

            var result = userService.authenticate(token);

            if(result != null) {
                return ResponseEntity.ok(result);
            }else{
                return new ResponseEntity<>("Error to auth user", HttpStatus.UNAUTHORIZED);
            }


        } catch (Exception ex) {
            return new ResponseEntity<>("Error to auth user", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
