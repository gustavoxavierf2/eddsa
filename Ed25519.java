import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Ed25519 (EdDSA sobre a curva de Edwards "edwards25519") implementado do zero,
 * seguindo a RFC 8032, seção 5.1.
 *
 * O algoritmo (aritmética da curva, geração de chave, assinatura e verificação) foi
 * escrito na mão. Do JDK usamos apenas ferramentas genéricas: BigInteger (números
 * grandes) e MessageDigest (SHA-512, a função de hash exigida pelo Ed25519).
 *
 * ATENÇÃO: versão DIDÁTICA. Não é "constant-time", então não serve para produção
 * (ataques de canal lateral). Em produção use uma biblioteca auditada.
 */
public final class Ed25519 {

    private Ed25519() {}

    /** Se true, imprime os valores intermediários de sign() e verify(). */
    public static boolean verbose = false;

    // ------------------------------------------------------------------
    // Parâmetros da curva
    // ------------------------------------------------------------------

    /** Primo do corpo: p = 2^255 - 19 (de onde vem o nome "25519"). */
    static final BigInteger P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));

    /** Ordem do ponto base (quantos múltiplos de B existem): l = 2^252 + 27742317777372353535851937790883648493. */
    static final BigInteger L = BigInteger.ONE.shiftLeft(252)
            .add(new BigInteger("27742317777372353535851937790883648493"));

    /** Constante d da equação  -x^2 + y^2 = 1 + d*x^2*y^2  (d = -121665/121666 mod p). */
    static final BigInteger D = BigInteger.valueOf(-121665)
            .multiply(inv(BigInteger.valueOf(121666))).mod(P);

    /** Raiz quadrada de -1 módulo p (usada ao descomprimir pontos). */
    static final BigInteger SQRT_M1 = BigInteger.TWO.modPow(P.subtract(BigInteger.ONE).shiftRight(2), P);

    /** Ponto base B (gerador). Y = 4/5; X é recuperado a partir de Y (bit de sinal 0). */
    static final Point B;
    static {
        BigInteger by = BigInteger.valueOf(4).multiply(inv(BigInteger.valueOf(5))).mod(P);
        BigInteger bx = recoverX(by, 0);
        B = new Point(bx, by, BigInteger.ONE, bx.multiply(by).mod(P));
    }

    // ------------------------------------------------------------------
    // Pontos da curva em coordenadas estendidas (X, Y, Z, T), com x = X/Z, y = Y/Z, xy = T/Z.
    // Essas coordenadas evitam fazer uma divisão (inversão modular) a cada soma.
    // ------------------------------------------------------------------

    static final class Point {
        final BigInteger x, y, z, t;
        Point(BigInteger x, BigInteger y, BigInteger z, BigInteger t) {
            this.x = x; this.y = y; this.z = z; this.t = t;
        }
    }

    /** Elemento neutro da soma: o ponto (0, 1). */
    static final Point NEUTRAL = new Point(BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO);

    /** Soma de dois pontos (fórmula completa, serve também para dobrar um ponto). */
    static Point add(Point p, Point q) {
        BigInteger a = p.y.subtract(p.x).multiply(q.y.subtract(q.x)).mod(P);
        BigInteger b = p.y.add(p.x).multiply(q.y.add(q.x)).mod(P);
        BigInteger c = p.t.multiply(BigInteger.TWO).multiply(D).multiply(q.t).mod(P);
        BigInteger d = p.z.multiply(BigInteger.TWO).multiply(q.z).mod(P);
        BigInteger e = b.subtract(a);
        BigInteger f = d.subtract(c);
        BigInteger g = d.add(c);
        BigInteger h = b.add(a);
        return new Point(
                e.multiply(f).mod(P),
                g.multiply(h).mod(P),
                f.multiply(g).mod(P),
                e.multiply(h).mod(P));
    }

    /** Multiplicação escalar s * point, por "dobra e soma" (double-and-add). */
    static Point multiply(BigInteger s, Point point) {
        Point result = NEUTRAL;
        Point addend = point;
        for (int i = 0; i < s.bitLength(); i++) {
            if (s.testBit(i)) {
                result = add(result, addend);
            }
            addend = add(addend, addend);
        }
        return result;
    }

    /** Dois pontos são iguais se x1/z1 == x2/z2 e y1/z1 == y2/z2 (sem dividir). */
    static boolean equal(Point p, Point q) {
        if (!p.x.multiply(q.z).subtract(q.x.multiply(p.z)).mod(P).equals(BigInteger.ZERO)) return false;
        return p.y.multiply(q.z).subtract(q.y.multiply(p.z)).mod(P).equals(BigInteger.ZERO);
    }

    // ------------------------------------------------------------------
    // Codificação de pontos (32 bytes): y em little-endian + bit de sinal de x no bit 255
    // ------------------------------------------------------------------

    static byte[] compress(Point p) {
        BigInteger zinv = inv(p.z);
        BigInteger x = p.x.multiply(zinv).mod(P);
        BigInteger y = p.y.multiply(zinv).mod(P);
        if (x.testBit(0)) {
            y = y.setBit(255);
        }
        return toLittleEndian(y, 32);
    }

    /** Retorna null se os bytes não representam um ponto válido da curva. */
    static Point decompress(byte[] b) {
        if (b.length != 32) return null;
        BigInteger y = fromLittleEndian(b);
        int sign = y.testBit(255) ? 1 : 0;
        y = y.clearBit(255);
        if (y.compareTo(P) >= 0) return null;
        BigInteger x = recoverX(y, sign);
        if (x == null) return null;
        return new Point(x, y, BigInteger.ONE, x.multiply(y).mod(P));
    }

    /** Da equação da curva: x^2 = (y^2 - 1) / (d*y^2 + 1). Retorna null se não existir x. */
    static BigInteger recoverX(BigInteger y, int sign) {
        BigInteger y2 = y.multiply(y).mod(P);
        BigInteger x2 = y2.subtract(BigInteger.ONE).multiply(inv(D.multiply(y2).add(BigInteger.ONE))).mod(P);
        if (x2.signum() == 0) {
            return sign == 1 ? null : BigInteger.ZERO;
        }
        // Candidato a raiz quadrada (p ≡ 5 mod 8): x = x2^((p+3)/8)
        BigInteger x = x2.modPow(P.add(BigInteger.valueOf(3)).shiftRight(3), P);
        if (!x.multiply(x).subtract(x2).mod(P).equals(BigInteger.ZERO)) {
            x = x.multiply(SQRT_M1).mod(P);
        }
        if (!x.multiply(x).subtract(x2).mod(P).equals(BigInteger.ZERO)) {
            return null; // x2 não é quadrado perfeito: y inválido
        }
        if ((x.testBit(0) ? 1 : 0) != sign) {
            x = P.subtract(x);
        }
        return x;
    }

    // ------------------------------------------------------------------
    // API do EdDSA: chave pública, assinar e verificar
    // ------------------------------------------------------------------

    /** Resultado do "secret expand": o escalar secreto a e o prefixo usado no nonce. */
    private static final class Expanded {
        final BigInteger a;
        final byte[] prefix;
        Expanded(BigInteger a, byte[] prefix) { this.a = a; this.prefix = prefix; }
    }

    /**
     * h = SHA-512(seed). Os 32 primeiros bytes viram o escalar secreto 'a' (com "clamp"),
     * os 32 últimos viram o 'prefix' que alimenta o nonce determinístico.
     */
    private static Expanded expand(byte[] seed) {
        if (seed.length != 32) throw new IllegalArgumentException("A seed deve ter 32 bytes");
        byte[] h = sha512(seed);
        byte[] lower = Arrays.copyOfRange(h, 0, 32);
        // Clamp: zera os 3 bits mais baixos (a vira múltiplo de 8, elimina o cofator),
        // zera o bit 255 e liga o bit 254 (a fica sempre grande, com tamanho fixo).
        lower[0] &= (byte) 0xf8;
        lower[31] &= (byte) 0x7f;
        lower[31] |= (byte) 0x40;
        return new Expanded(fromLittleEndian(lower), Arrays.copyOfRange(h, 32, 64));
    }

    /** Chave pública A = a * B, codificada em 32 bytes. */
    public static byte[] publicKey(byte[] seed) {
        Expanded e = expand(seed);
        return compress(multiply(e.a, B));
    }

    /** Assina a mensagem. Determinístico: mesma seed + mesma mensagem = mesma assinatura. */
    public static byte[] sign(byte[] seed, byte[] message) {
        Expanded e = expand(seed);
        byte[] pub = compress(multiply(e.a, B));

        BigInteger r = hashModL(e.prefix, message);          // nonce derivado (não é aleatório!)
        byte[] rEnc = compress(multiply(r, B));              // R = r * B
        BigInteger k = hashModL(rEnc, pub, message);         // desafio k = H(R || A || M)
        BigInteger s = r.add(k.multiply(e.a)).mod(L);        // S = (r + k*a) mod l

        if (verbose) {
            System.out.println("  [sign] a      = " + Hex.toHex(toLittleEndian(e.a, 32)));
            System.out.println("  [sign] prefix = " + Hex.toHex(e.prefix));
            System.out.println("  [sign] A      = " + Hex.toHex(pub));
            System.out.println("  [sign] r      = " + Hex.toHex(toLittleEndian(r, 32)));
            System.out.println("  [sign] R      = " + Hex.toHex(rEnc));
            System.out.println("  [sign] k      = " + Hex.toHex(toLittleEndian(k, 32)));
            System.out.println("  [sign] S      = " + Hex.toHex(toLittleEndian(s, 32)));
        }

        byte[] sig = new byte[64];
        System.arraycopy(rEnc, 0, sig, 0, 32);
        System.arraycopy(toLittleEndian(s, 32), 0, sig, 32, 32);
        return sig;
    }

    /** Verifica a assinatura. Retorna false para qualquer entrada inválida. */
    public static boolean verify(byte[] pub, byte[] message, byte[] sig) {
        if (pub.length != 32 || sig.length != 64) return false;

        Point a = decompress(pub);
        if (a == null) return false;
        byte[] rEnc = Arrays.copyOfRange(sig, 0, 32);
        Point r = decompress(rEnc);
        if (r == null) return false;
        BigInteger s = fromLittleEndian(Arrays.copyOfRange(sig, 32, 64));
        if (s.compareTo(L) >= 0) return false;               // S precisa estar em [0, l)

        BigInteger k = hashModL(rEnc, pub, message);
        Point left = multiply(s, B);                         // S * B
        Point right = add(r, multiply(k, a));                // R + k * A

        if (verbose) {
            System.out.println("  [verify] k          = " + Hex.toHex(toLittleEndian(k, 32)));
            System.out.println("  [verify] S*B        = " + Hex.toHex(compress(left)));
            System.out.println("  [verify] R + k*A    = " + Hex.toHex(compress(right)));
        }
        return equal(left, right);
    }

    // ------------------------------------------------------------------
    // Funções auxiliares
    // ------------------------------------------------------------------

    /** SHA-512 das partes concatenadas, lido como inteiro little-endian, reduzido módulo l. */
    private static BigInteger hashModL(byte[]... parts) {
        int total = 0;
        for (byte[] part : parts) total += part.length;
        byte[] all = new byte[total];
        int pos = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, all, pos, part.length);
            pos += part.length;
        }
        return fromLittleEndian(sha512(all)).mod(L);
    }

    /** SHA-512 (do JDK). O Ed25519 especifica SHA-512 como função de hash. */
    private static byte[] sha512(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-512").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Inverso modular em Z_p, usando o Pequeno Teorema de Fermat: x^(p-2) mod p. */
    static BigInteger inv(BigInteger x) {
        return x.modPow(P.subtract(BigInteger.TWO), P);
    }

    /** bytes little-endian -> inteiro não negativo. */
    static BigInteger fromLittleEndian(byte[] b) {
        byte[] be = new byte[b.length];
        for (int i = 0; i < b.length; i++) be[i] = b[b.length - 1 - i];
        return new BigInteger(1, be);
    }

    /** inteiro não negativo -> 'len' bytes little-endian. */
    static byte[] toLittleEndian(BigInteger v, int len) {
        byte[] out = new byte[len];
        BigInteger x = v;
        BigInteger mask = BigInteger.valueOf(0xff);
        for (int i = 0; i < len; i++) {
            out[i] = (byte) x.and(mask).intValue();
            x = x.shiftRight(8);
        }
        return out;
    }
}
