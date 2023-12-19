package org.example.cognitoAuthSpring3.controller;

import org.example.cognitoAuthSpring3.model.UserGroupAddRequest;
import org.example.cognitoAuthSpring3.model.UserRegisterRequest;
import org.example.cognitoAuthSpring3.service.contract.AdminService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
//@EnableWebMvc
@RequestMapping("/api/v1/admin")
public class AdminController {
    private AdminService adminService;

    @Autowired
    public AdminController(AdminService adminService){
        this.adminService = adminService;
    }

    @PostMapping("/user")
    public ResponseEntity<String> createUser(@RequestBody UserRegisterRequest user) {
        Boolean result = false;

        try{
            result = adminService.createUser(user.getName(), user.getUserName(), user.getEmail());

            if(result != null && result)
                return new ResponseEntity<>("User successfully created", HttpStatus.CREATED);
            else
                return new ResponseEntity<>("Error to create user", HttpStatus.BAD_REQUEST);

        }catch (Exception ex){
            return new ResponseEntity<>("Error to create user", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @DeleteMapping("/user/{userName}")
    public ResponseEntity<?> deleteUser(@PathVariable String userName){

        try{
            adminService.deleteUser(userName);
            return new ResponseEntity<>("User successfully removed ", HttpStatus.OK);
        }catch (Exception ex){

            return new ResponseEntity<>("Error to remove User", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PutMapping("/user/{userName}/confirm")
    public ResponseEntity<?> confirmUser(@PathVariable String userName){

        try{
            adminService.confirmUser(userName);
            return new ResponseEntity<>("User successfully confirmed", HttpStatus.OK);
        }catch (Exception ex){

            return new ResponseEntity<>("Error to confirm User", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
    @PostMapping("/user/group/add")
    public ResponseEntity<?> addToGroup(@RequestBody UserGroupAddRequest userGroupAddRequest) {
        try{
            adminService.addUserToGroup(userGroupAddRequest.getUserName(), userGroupAddRequest.getGroup());
            return new ResponseEntity<>("User successfully added to the group " + userGroupAddRequest.getGroup(), HttpStatus.OK);
        }catch (Exception ex){

            return new ResponseEntity<>("Error to add User to group "+ userGroupAddRequest.getGroup(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

}
