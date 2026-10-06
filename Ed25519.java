import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * Ed25519 (EdDSA, RFC 8032 §5.1) implementado na mão, só com BigInteger e SHA-512 do JDK.
 * Versão DIDÁTICA: não é constant-time, não usar em produção.
 */
public final class Ed25519 {

    private Ed25519() {}

    // p = 2^255 - 19: primo do corpo, toda conta de coordenada é mod p
    static final BigInteger P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));

    // l: ordem do ponto base B, toda conta de escalar (a, r, k, S) é mod l
    static final BigInteger L = BigInteger.ONE.shiftLeft(252)
            .add(new BigInteger("27742317777372353535851937790883648493"));

    // d: constante da curva  -x² + y² = 1 + d·x²·y²
    static final BigInteger D = BigInteger.valueOf(-121665)
            .multiply(inv(BigInteger.valueOf(121666))).mod(P);

    // raiz quadrada de -1 mod p, usada em recoverX()
    static final BigInteger SQRT_M1 = BigInteger.TWO.modPow(P.subtract(BigInteger.ONE).shiftRight(2), P);

    // ponto em coordenadas estendidas: x = X/Z, y = Y/Z, x·y = T/Z (evita divisões nas somas)
    record Point(BigInteger x, BigInteger y, BigInteger z, BigInteger t) {}

    // ponto neutro (0, 1): o "zero" da soma de pontos
    static final Point NEUTRAL = new Point(BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO);

    // ponto base B (gerador): y = 4/5, x positivo
    static final Point B;
    static {
        BigInteger by = BigInteger.valueOf(4).multiply(inv(BigInteger.valueOf(5))).mod(P);
        BigInteger bx = recoverX(by, 0);
        B = new Point(bx, by, BigInteger.ONE, bx.multiply(by).mod(P));
    }

    /** §5.1.4 Soma de pontos P + Q (também serve para dobrar: P + P). */
    static Point add(Point p, Point q) {
        BigInteger a = p.y.subtract(p.x).multiply(q.y.subtract(q.x)).mod(P);
        BigInteger b = p.y.add(p.x).multiply(q.y.add(q.x)).mod(P);
        BigInteger c = p.t.multiply(BigInteger.TWO).multiply(D).multiply(q.t).mod(P);
        BigInteger d = p.z.multiply(BigInteger.TWO).multiply(q.z).mod(P);
        BigInteger e = b.subtract(a), f = d.subtract(c), g = d.add(c), h = b.add(a);
        return new Point(e.multiply(f).mod(P), g.multiply(h).mod(P),
                         f.multiply(g).mod(P), e.multiply(h).mod(P));
    }

    /** §5.1.4 Multiplicação escalar s·Q por "dobra e soma" (o if por bit é o que a torna não constant-time). */
    static Point multiply(BigInteger s, Point q) {
        Point result = NEUTRAL;
        for (int i = 0; i < s.bitLength(); i++) {
            if (s.testBit(i)) result = add(result, q);
            q = add(q, q);
        }
        return result;
    }

    /** Compara dois pontos (x1/z1 == x2/z2 e y1/z1 == y2/z2) multiplicando em cruz, sem dividir. */
    static boolean equal(Point p, Point q) {
        return p.x.multiply(q.z).subtract(q.x.multiply(p.z)).mod(P).signum() == 0
            && p.y.multiply(q.z).subtract(q.y.multiply(p.z)).mod(P).signum() == 0;
    }

    /** §5.1.2 Codifica o ponto em 32 bytes: y em little-endian + bit 255 = paridade de x. */
    static byte[] compress(Point p) {
        BigInteger zinv = inv(p.z);
        BigInteger x = p.x.multiply(zinv).mod(P);
        BigInteger y = p.y.multiply(zinv).mod(P);
        if (x.testBit(0)) y = y.setBit(255);
        return toLittleEndian(y, 32);
    }

    /** §5.1.3 Decodifica 32 bytes em ponto; retorna null se não for um ponto da curva. */
    static Point decompress(byte[] bytes) {
        if (bytes.length != 32) return null;
        BigInteger y = fromLittleEndian(bytes);
        int sign = y.testBit(255) ? 1 : 0;
        y = y.clearBit(255);
        if (y.compareTo(P) >= 0) return null;
        BigInteger x = recoverX(y, sign);
        if (x == null) return null;
        return new Point(x, y, BigInteger.ONE, x.multiply(y).mod(P));
    }

    /** §5.1.3 Recupera x pela equação x² = (y² - 1) / (d·y² + 1); null se não houver raiz. */
    static BigInteger recoverX(BigInteger y, int sign) {
        BigInteger y2 = y.multiply(y).mod(P);
        BigInteger x2 = y2.subtract(BigInteger.ONE).multiply(inv(D.multiply(y2).add(BigInteger.ONE))).mod(P);
        if (x2.signum() == 0) return sign == 1 ? null : BigInteger.ZERO;
        BigInteger x = x2.modPow(P.add(BigInteger.valueOf(3)).shiftRight(3), P);
        if (!x.multiply(x).subtract(x2).mod(P).equals(BigInteger.ZERO)) x = x.multiply(SQRT_M1).mod(P);
        if (!x.multiply(x).subtract(x2).mod(P).equals(BigInteger.ZERO)) return null;
        if ((x.testBit(0) ? 1 : 0) != sign) x = P.subtract(x);
        return x;
    }

    // a: escalar secreto | prefix: semente do nonce r
    private record Expanded(BigInteger a, byte[] prefix) {}

    /** §5.1.5 h = SHA-512(seed); a = clamp(h[0..31]); prefix = h[32..63]. */
    private static Expanded expand(byte[] seed) {
        if (seed.length != 32) throw new IllegalArgumentException("A seed deve ter 32 bytes");
        byte[] h = sha512(seed);
        byte[] lower = Arrays.copyOfRange(h, 0, 32);
        lower[0] &= (byte) 0xf8;
        lower[31] &= (byte) 0x7f;
        lower[31] |= (byte) 0x40;
        return new Expanded(fromLittleEndian(lower), Arrays.copyOfRange(h, 32, 64));
    }

    /** §5.1.5 Gera a chave pública A = a·B (32 bytes). */
    public static byte[] publicKey(byte[] seed) {
        Expanded e = expand(seed);
        byte[] A = compress(multiply(e.a, B));
        print("a (escalar secreto)", "nº secreto de pulos", e.a);
        print("prefix (semente do nonce)", "tempero secreto do r", e.prefix);
        print("A (chave pública)", "onde parou após a pulos de B", A);
        return A;
    }

    /** §5.1.6 Assina: r = H(prefix||M), R = r·B, k = H(R||A||M), S = (r + k·a) mod l, assinatura = R||S. */
    public static byte[] sign(byte[] seed, byte[] message) {
        Expanded e = expand(seed);
        byte[] A = compress(multiply(e.a, B));
        BigInteger r = hashModL(e.prefix, message);
        byte[] R = compress(multiply(r, B));
        BigInteger k = hashModL(R, A, message);
        BigInteger S = r.add(k.multiply(e.a)).mod(L);
        print("r (nonce)", "pulos de uso único", r);
        print("R (nonce público = r·B)", "onde parou após r pulos", R);
        print("k (desafio = H(R||A||M))", "pergunta sobre R, A e M", k);
        print("S (resposta = r + k·a)", "resposta que exige saber a", S);

        byte[] sig = new byte[64];
        System.arraycopy(R, 0, sig, 0, 32);
        System.arraycopy(toLittleEndian(S, 32), 0, sig, 32, 32);
        return sig;
    }

    /** §5.1.7 Verifica: decodifica A, R, S; k = H(R||A||M); aceita se S·B == R + k·A. */
    public static boolean verify(byte[] publicKey, byte[] message, byte[] sig) {
        if (publicKey.length != 32 || sig.length != 64) return false;
        Point A = decompress(publicKey);
        byte[] rBytes = Arrays.copyOfRange(sig, 0, 32);
        Point R = decompress(rBytes);
        BigInteger S = fromLittleEndian(Arrays.copyOfRange(sig, 32, 64));
        if (A == null || R == null || S.compareTo(L) >= 0) return false;

        BigInteger k = hashModL(rBytes, publicKey, message);
        Point left = multiply(S, B);
        Point right = add(R, multiply(k, A));
        print("k (desafio recalculado)", "mesma pergunta, refeita", k);
        print("S·B (lado esquerdo)", "S pulos a partir de B", compress(left));
        print("R + k·A (lado direito)", "de R, mais k·a pulos", compress(right));
        return equal(left, right);
    }

    /** SHA-512 das partes concatenadas, lido em little-endian e reduzido mod l. */
    private static BigInteger hashModL(byte[]... parts) {
        MessageDigest md = sha512();
        for (byte[] part : parts) md.update(part);
        return fromLittleEndian(md.digest()).mod(L);
    }

    /** SHA-512 de um array de bytes. */
    private static byte[] sha512(byte[] data) {
        return sha512().digest(data);
    }

    /** Instância do SHA-512 do JDK (a função de hash exigida pelo Ed25519). */
    private static MessageDigest sha512() {
        try {
            return MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Inverso modular 1/x mod p pelo Pequeno Teorema de Fermat: x^(p-2). */
    static BigInteger inv(BigInteger x) {
        return x.modPow(P.subtract(BigInteger.TWO), P);
    }

    /** Bytes little-endian -> inteiro (o Ed25519 grava números com o byte menos significativo primeiro). */
    static BigInteger fromLittleEndian(byte[] b) {
        byte[] be = new byte[b.length];
        for (int i = 0; i < b.length; i++) be[i] = b[b.length - 1 - i];
        return new BigInteger(1, be);
    }

    /** Inteiro -> 'len' bytes little-endian. */
    static byte[] toLittleEndian(BigInteger v, int len) {
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) v.intValue();
            v = v.shiftRight(8);
        }
        return out;
    }

    /** Imprime um escalar como 32 bytes em hex. */
    static void print(String nome, String exemplo, BigInteger valor) {
        print(nome, exemplo, toLittleEndian(valor, 32));
    }

    /** Imprime bytes em hex. */
    static void print(String nome, String exemplo, byte[] valor) {
        print(nome, exemplo, HexFormat.of().formatHex(valor));
    }

    /** Imprime "nome (significado) - exemplo = valor" alinhado em colunas. */
    static void print(String nome, String exemplo, String valor) {
        System.out.printf("  %-26s - %-28s = %s%n", nome, exemplo, valor);
    }
}
