import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Scanner;


public class Main {

    // Texto cifrado
    private static byte[] textoCifrado;

    // Chave em bytes
    private static byte[] keyBytes = new byte[16];

    public static void main(String[] args) {

        // Adiciona o provedor de segurança Bouncy Castle FIPS (Federal Information Processing Standards) como um provedor de segurança no ambiente Java.
        Security.addProvider(new BouncyCastleFipsProvider());

        // Chama o método para criptografar a mensagem
        criptografarMsg();

        // Chama o método para descriptografar a mensagem
        descriptografarMsg();
    }

    private static void criptografarMsg() {
        try {
            // Gera uma chave aleatória para o algoritmo IDEA
            KeyGenerator geradorChave = KeyGenerator.getInstance("IDEA", "BCFIPS");
            geradorChave.init(new SecureRandom());
            Key chave = geradorChave.generateKey();

            // Obtém os bytes da chave gerada
            keyBytes = chave.getEncoded();

            // Cria o objeto Cipher para criptografar a mensagem
            Cipher criptografar = Cipher.getInstance("IDEA/ECB/PKCS5Padding", "BCFIPS");

            // Inicializa o Cipher no modo de criptografia com a chave
            criptografar.init(Cipher.ENCRYPT_MODE, chave);

            // Lê a mensagem a ser criptografada
            Scanner ler = new Scanner(System.in);
            String mensagem = ler.nextLine();

            // Criptografa a mensagem
            textoCifrado = criptografar.doFinal(mensagem.getBytes());

            // Imprime o texto cifrado
            System.out.println("Texto cifrado: " + new String(textoCifrado, StandardCharsets.UTF_8));

        } catch (Exception e) {
            System.out.println(e);
        }
    }

    private static void descriptografarMsg() {
        try {

            // Cria uma chave secreta usando os bytes da chave que foi gerada ao criptografar
            SecretKeySpec sks = new SecretKeySpec(keyBytes, "IDEA/ECB/PKCS5Padding");

            // Cria o objeto Cipher para descriptografar a mensagem
            Cipher descriptografar = Cipher.getInstance("IDEA/ECB/PKCS5Padding", "BCFIPS");

            // Inicializa o Cipher no modo de descriptografia com a chave
            descriptografar.init(Cipher.DECRYPT_MODE, sks);

            // Descriptografa a mensagem
            byte[] plaintext = descriptografar.doFinal(textoCifrado);

            // Imprime o texto descriptografado
            System.out.println("Texto descriptografado: " + new String(plaintext, StandardCharsets.UTF_8));

        } catch (Exception e) {
            System.out.println(e);
        }
    }
}
