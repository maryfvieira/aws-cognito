package org.example.cognitoAuthSpring3.service.contract;

public interface AdminService {
    Boolean createUser(String name, String userName, String email);
    void deleteUser(String userName);
    void addUserToGroup(String username, String groupName);
    void confirmUser(String userName);
}
