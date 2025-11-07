// BrokenAuth.java
import java.util.*;

public class BrokenAuth {
    static Map<String, String> users = Map.of("admin", "admin123");

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        System.out.print("Username: ");
        String user = sc.nextLine();
        System.out.print("Password: ");
        String pass = sc.nextLine();

        if (users.containsKey(user) && users.get(user).equals(pass)) {
            System.out.println("Accesso consentito");
        } else {
            System.out.println("Accesso negato");
        }
    }
}
