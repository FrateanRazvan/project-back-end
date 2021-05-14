package ubb.postuniv.Project2021.security;

public enum AplicationUserPermission {

    USER_READ("user: read"),
    USER_WRITE("user: write"),
    PROJECT_READ("project: read"),
    PROJECT_WRITE("project: write");

    private final String permission;


    AplicationUserPermission(String permission) {
        this.permission = permission;
    }

    public String getPermission() {
        return permission;
    }
}
