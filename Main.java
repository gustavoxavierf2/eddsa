import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws Exception {
        Scanner in = new Scanner(System.in);

        titulo("1. GERAR CHAVE");
        byte[] seed = new byte[32];
        new SecureRandom().nextBytes(seed);
        Ed25519.print("seed (chave privada)", "32 bytes sorteados", seed);
        byte[] publicKey = Ed25519.publicKey(seed);

        titulo("2. ASSINAR");
        String entrada = ler(in, "Mensagem ou caminho do arquivo: ");
        byte[] sig = Ed25519.sign(seed, lerMensagem(entrada));
        Ed25519.print("R || S (assinatura)", "parada R + resposta S", sig);

        titulo("3. VERIFICAR");
        String outra = ler(in, "Mensagem ou caminho do arquivo (Enter = a mesma): ");
        boolean valida = Ed25519.verify(publicKey, lerMensagem(outra.isEmpty() ? entrada : outra), sig);
        System.out.println(valida ? "\nASSINATURA VÁLIDA" : "\nASSINATURA INVÁLIDA");
    }

    private static byte[] lerMensagem(String entrada) throws IOException {
        try {
            Path arquivo = Path.of(entrada.replace("\"", ""));
            if (Files.isRegularFile(arquivo)) {
                Ed25519.print("M (mensagem)", "o que será assinado", "arquivo " + arquivo.getFileName() + " (" + Files.size(arquivo) + " bytes)");
                return Files.readAllBytes(arquivo);
            }
        } catch (InvalidPathException ignored) {
        }
        Ed25519.print("M (mensagem)", "o que será assinado", "\"" + entrada + "\"");
        return entrada.getBytes(StandardCharsets.UTF_8);
    }

    private static String ler(Scanner in, String pergunta) {
        System.out.print(pergunta);
        return in.hasNextLine() ? in.nextLine() : "";
    }

    private static void titulo(String t) {
        System.out.println("\n=== " + t + " ===");
    }
}
