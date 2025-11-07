// UnvalidatedRedirect.java
// UnvalidatedRedirect.java
import java.util.Scanner;
import java.io.IOException;

public class UnvalidatedRedirect {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);

        System.out.print("Inserisci URL di destinazione: ");
        String url = sc.nextLine();

        // 🔴 VULNERABILITÀ: Nessuna validazione dell'URL
        System.out.println("Reindirizzamento a: " + url);

        // Simula un redirect HTTP
        redirectTo(url);

        sc.close();
    }

    // Metodo che simula un redirect HTTP 302
    private static void redirectTo(String url) {
        System.out.println("\n=== SIMULAZIONE HTTP REDIRECT ===");
        System.out.println("HTTP/1.1 302 Found");
        System.out.println("Location: " + url);
        System.out.println("=================================\n");

        // In un'app web reale, questo sarebbe:
        // response.sendRedirect(url);

        // Opzionalmente, apri l'URL nel browser (solo per demo)
        try {
            if (System.getProperty("os.name").toLowerCase().contains("win")) {
                Runtime.getRuntime().exec("cmd /c start " + url);
            } else if (System.getProperty("os.name").toLowerCase().contains("mac")) {
                Runtime.getRuntime().exec("open " + url);
            } else {
                Runtime.getRuntime().exec("xdg-open " + url);
            }
        } catch (IOException e) {
            System.err.println("Impossibile aprire il browser: " + e.getMessage());
        }
    }
}