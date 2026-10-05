import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Demonstração do Ed25519 (EdDSA) implementado na mão.
 *
 * Compilar:  javac *.java
 * Executar:  java Main
 */
public class Main {

    public static void main(String[] args) {
        demonstracao();
        testesRfc8032();
    }

    // ------------------------------------------------------------------
    // Parte 1: demonstração para a apresentação
    // ------------------------------------------------------------------
    static void demonstracao() {
        titulo("1. Gerando o par de chaves");
        byte[] seed = new byte[32];
        new SecureRandom().nextBytes(seed);              // chave privada: 32 bytes aleatórios
        byte[] pub = Ed25519.publicKey(seed);            // chave pública: A = a * B
        System.out.println("Chave privada (seed): " + Hex.toHex(seed));
        System.out.println("Chave pública       : " + Hex.toHex(pub));

        titulo("2. Assinando uma mensagem");
        byte[] msg = "Transferir R$ 100,00 para Caio".getBytes(StandardCharsets.UTF_8);
        System.out.println("Mensagem: \"" + new String(msg, StandardCharsets.UTF_8) + "\"");
        Ed25519.verbose = true;
        byte[] sig = Ed25519.sign(seed, msg);
        Ed25519.verbose = false;
        System.out.println("Assinatura (R || S, 64 bytes): " + Hex.toHex(sig));

        titulo("3. Verificando a assinatura");
        Ed25519.verbose = true;
        boolean ok = Ed25519.verify(pub, msg, sig);
        Ed25519.verbose = false;
        System.out.println("Assinatura válida? " + ok);

        titulo("4. Mensagem alterada (1 caractere) -> deve falhar");
        byte[] adulterada = "Transferir R$ 900,00 para Caio".getBytes(StandardCharsets.UTF_8);
        System.out.println("Assinatura válida? " + Ed25519.verify(pub, adulterada, sig));

        titulo("5. Assinatura alterada (1 bit) -> deve falhar");
        byte[] sigRuim = sig.clone();
        sigRuim[10] ^= 0x01;
        System.out.println("Assinatura válida? " + Ed25519.verify(pub, msg, sigRuim));

        titulo("6. Chave pública de outra pessoa -> deve falhar");
        byte[] outraSeed = new byte[32];
        new SecureRandom().nextBytes(outraSeed);
        System.out.println("Assinatura válida? " + Ed25519.verify(Ed25519.publicKey(outraSeed), msg, sig));

        titulo("7. Determinismo: assinar duas vezes a mesma mensagem");
        byte[] sig2 = Ed25519.sign(seed, msg);
        System.out.println("As duas assinaturas são idênticas? " + Arrays.equals(sig, sig2));
    }

    // ------------------------------------------------------------------
    // Parte 2: vetores de teste oficiais da RFC 8032 (seção 7.1)
    // Se a implementação gerar exatamente estes valores, ela está correta.
    // ------------------------------------------------------------------
    static void testesRfc8032() {
        titulo("8. Vetores de teste da RFC 8032");
        String[][] vetores = {
            { // TEST 1 (mensagem vazia)
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            },
            { // TEST 2 (1 byte)
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
            },
            { // TEST 3 (2 bytes)
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
            }
        };

        int passou = 0;
        for (int i = 0; i < vetores.length; i++) {
            byte[] seed = Hex.fromHex(vetores[i][0]);
            byte[] msg = Hex.fromHex(vetores[i][2]);

            boolean pubOk = Hex.toHex(Ed25519.publicKey(seed)).equals(vetores[i][1]);
            byte[] sig = Ed25519.sign(seed, msg);
            boolean sigOk = Hex.toHex(sig).equals(vetores[i][3]);
            boolean verOk = Ed25519.verify(Hex.fromHex(vetores[i][1]), msg, sig);

            boolean tudo = pubOk && sigOk && verOk;
            if (tudo) passou++;
            System.out.printf("TEST %d: chave pública %s | assinatura %s | verificação %s%n",
                    i + 1, ok(pubOk), ok(sigOk), ok(verOk));
        }
        System.out.println(passou + "/" + vetores.length + " vetores passaram.");
    }

    private static String ok(boolean b) { return b ? "OK" : "FALHOU"; }

    private static void titulo(String t) {
        System.out.println();
        System.out.println("=== " + t + " ===");
    }
}
