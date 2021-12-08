import sun.security.x509.*;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.SQLOutput;
import java.util.Base64;
import java.util.Date;

public class Main {
    public static void apkSign() {
        File file = new File("signconfig/sign.conf");

        if (file.exists()) {
            try {
                FileInputStream fileInputStream = new FileInputStream(file);
                InputStreamReader inputStreamReader = new InputStreamReader(fileInputStream);
                BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                String config = bufferedReader.readLine();

                if (config != null) {
                    if (config.contains("signapk.jar")) {
                        //使用signapk.jar,如:java -jar signapk.jar platform.x509.pem platform.pk8 MyDemo.apk MyDemo_signed.apk
                    } else {
                        //使用jarsigner,如:jarsigner -verbose -keystore abc.keystore [-storepass feelyou.info] -signedjar 123x.apk 123.apk hi
                        config = String.format(config, "C:\\Users\\sertac.demiray\\Desktop\\keystore1.keystore", "123456", "123456", "C:\\Users\\sertac.demiray\\Desktop\\app-debug.apk", "main");


                        String result = CommandUtil.exec(config);
                        System.out.print(result);
                    }
                }
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }


    private static X509Certificate generateCertificate(String dn, int validity, String sigAlgName) throws GeneralSecurityException, IOException {
        PrivateKey privateKey = loadPrivateKey();
        X509CertInfo info = new X509CertInfo();

        Date from = new Date();
        Date to = new Date(from.getTime() + validity * 1000L * 24L * 60L * 60L);

        CertificateValidity interval = new CertificateValidity(from, to);
        BigInteger serialNumber = new BigInteger(64, new SecureRandom());
        X500Name owner = new X500Name(dn);
        AlgorithmId sigAlgId = new AlgorithmId(AlgorithmId.sha1WithRSAEncryption_oid);

        info.set(X509CertInfo.VALIDITY, interval);
        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serialNumber));
        info.set(X509CertInfo.SUBJECT, owner);
        info.set(X509CertInfo.ISSUER, owner);
        info.set(X509CertInfo.KEY, new CertificateX509Key(loadPublicKey()));
        info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(sigAlgId));

        // Sign the cert to identify the algorithm that's used.
        X509CertImpl certificate = new X509CertImpl(info);
        certificate.sign(privateKey, sigAlgName);
        // Update the algorith, and resign.
        sigAlgId = (AlgorithmId) certificate.get(X509CertImpl.SIG_ALG);
        info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, sigAlgId);
        certificate = new X509CertImpl(info);
        certificate.sign(loadPrivateKey(), sigAlgName);

        return certificate;
    }


    public static RSAPrivateKey loadPrivateKey() throws GeneralSecurityException, IOException {
        String PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----" +
                "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCEvRs3kBNplnOtdB3oh+CoYNPjC4ww3bNK+3WSeKuyf7qtrDlVaxPWEIjdrsZlCdgcIA6gTOh7znl7iJ" +
                "mXpDfoWiMnkOAg6HmctmNGPdOE2bS8AbzO5KR9FE6as/dJY7ASEjUOhz0eo2TiRzNSFttun0IAWs75cpegNYtchM+iIYR0N2I0ec0L8LP72vuKYP5spJFe2G59glskWS8T6R" +
                "AwSQ/UFE4ayhnsxAIB3yZLRB4Wj3UIh8EJRXqjFfeKthE16j3x2f7Se+4pIswJjaF0xoBmNPXQDKRjEhnpfXvheqiw4kRGPzmfhEPZMAAYY/Xb7NeLE8+pGvCK77IxEk9HAgMBA" +
                "AECggEAGBWDwbIXg5nzxS4DWzSEM6jV6SUoO5mONXWooHnalVmNkoNkJ7Z08+suGiLjBmQh3QCIBtfNeuE8s4hWbegy6KqqJDyqHe5wWlnRa2Y+YaVqoI4kJtnfan5rwLAUlzFKOg0p" +
                "qUgqc8uru0615hgVml21CQFw+lurXTs53QCP99efylOSfTBjp1yz3E8Pvlt1IjbsYsOFPiDGfVuuWAQ59A1nifFmqpG4H2Zu8hwXGIQj5CLDN8DF054NOPCyeoxVGvqaMZcCCiElCiW8OZj" +
                "5zlJS5UYv2LKIUTcsF3ZeXo6nAkvwzoEJXNS04yhZK4bnfAwsA2uVxVMGqD3VEkU+OQKBgQDLl6hlyzyIv3rrcxIfE2+nKldZuT7yFiKtgBAkiqF4PrpHXW01SlxdhU0Cj8wgar8Z1YCZJ/k6E1" +
                "9QPs4rcKqeTG2O4fXntu1EUWWxr9fxvgACOhJeh3hMQDf31H07XLPXE3+hGgji/jwc7ZZdRGIIUdX+xo7A0RuDz9c8QqRSRQKBgQCm6FO4jqM7IfnWNHUn3w1W4OdZ7XcKItNL8NafHRWwsiA9s" +
                "8vKYpR5Gi+JOAKXjMnmeUcFKJIyNuW9C/L8aENjbRPxLFOIIZ/cg/P+Ww/MMLZR6uweyfA6sKb+01l4qudhPC73QUVYzqnKpoJFKJ1NNv7BLkc+k0Ko63thEVI6GwKBgQCH827VAsEag9reLQoVzFH" +
                "Lq/+Gf6gj2lovx4uACz7F4AVeMGoDovNI1AHXyxRBNWcFJkfofgP0HwmPuVDNO0AD0v954TPnFoUcEMq6u7SUzg6Nbh/kFcxkBqIZEUDLCh1harjYaF00zxZvLsww3cAk1Bj1N7wNz9Ty0TBmIg4+jQ" +
                "KBgDkGUWxR13Uhk5Fa1Ngtfgo7xu9TkYM2CMj+XOV582ouQZOzNSJNcfq6NpmEOGZ85JJIxzn89Y4QcYeYaIlSOgvjPZf9lACDtHGL57X0eL5Dulbck5WlWt1Cc5vGq9/tTCZNgKJbe4zu9tXU89cbHDt" +
                "AWeO4owC/IVxDMCEm4NgXAoGAHGUnDd210dtwULXJ6JgpBntIV639O1BXpuw+l920mgz+XCAOYNJhgrQELgB/2KtBfXrTz8b9qFGeU1VvgKLhacIKhRylLyVVhlGdc6XBRd9GKx8PtP80upuIJM0pPbfC" +
                "jkcxNZGC3RsIloAcV3hkauAMwu0Pm0sDKdEu4myLYDY=" +
                "-----END RSA PRIVATE KEY-----";
        StringBuilder pkcs8Lines = new StringBuilder();
        BufferedReader rdr = new BufferedReader(new StringReader(PRIVATE_KEY));
        String line;
        while ((line = rdr.readLine()) != null) {
            pkcs8Lines.append(line);
        }

        // Remove the "BEGIN" and "END" lines, as well as any whitespace

        String pkcs8Pem = pkcs8Lines.toString();
        pkcs8Pem = pkcs8Pem.replaceAll("\\n+", "").replace("-----BEGIN RSA PRIVATE KEY-----", "").replace("-----END RSA PRIVATE KEY-----", "");

        byte[] encoded = org.apache.commons.codec.binary.Base64.decodeBase64(pkcs8Pem);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }

    public static RSAPublicKey loadPublicKey() throws GeneralSecurityException, IOException {

        String PUBLIC_KEY = "-----BEGIN RSA PUBLIC KEY-----\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhL0bN5ATaZZzrXQd6IfgqGDT4wuMMN2zSvt1knirsn+6ra\n" +
                "w5VWsT1hCI3a7GZQnYHCAOoEzoe855e4iZl6Q36FojJ5DgIOh5nLZjRj3ThNm0vAG8zuSkfRROmrP3SWOwEhI1Doc9HqNk4kczUhbbbp\n" +
                "9CAFrO+XKXoDWLXITPoiGEdDdiNHnNC/Cz+9r7imD+bKSRXthufYJbJFkvE+kQMEkP1BROGsoZ7MQCAd8mS0QeFo91CIfBCUV6oxX\n" +
                "3irYRNeo98dn+0nvuKSLMCY2hdMaAZjT10AykYxIZ6X174XqosOJERj85n4RD2TAAGGP12+zXixPPqRrwiu+yMRJPRwIDAQAB" +
                "-----END RSA PUBLIC KEY-----";
        StringBuilder pkcs8Lines = new StringBuilder();
        BufferedReader rdr = new BufferedReader(new StringReader(PUBLIC_KEY));
        String line;
        while ((line = rdr.readLine()) != null) {
            pkcs8Lines.append(line);
        }

        // Remove the "BEGIN" and "END" lines, as well as any whitespace

        String pkcs8Pem = pkcs8Lines.toString();
        pkcs8Pem = pkcs8Pem.replaceAll("\\n+", "")
                .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                .replace("-----END RSA PUBLIC KEY-----", "");

        byte[] data = Base64.getDecoder().decode((pkcs8Pem.getBytes()));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) fact.generatePublic(spec);

    }


    public static void main(String[] args) throws GeneralSecurityException, IOException {
        try (
                FileOutputStream fos = new FileOutputStream("C:\\Users\\sertac.demiray\\Desktop\\keystore1.keystore"); // CREATE FILE
        ) {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            //KeyPair keyPair = keyPairGenerator.generateKeyPair();
            // PrivateKey privateKey = keyPair.getPrivate();
            //System.out.println(privateKey);

            X509Certificate[] chain = {generateCertificate("cn=TEST", 365, "SHA256withRSA")};
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            keyStore.setKeyEntry("main", loadPrivateKey(), "123456".toCharArray(), chain);
            keyStore.store(fos, "123456".toCharArray());
        } catch (IOException | GeneralSecurityException e) {
            e.printStackTrace();
        }
        System.out.println("Worked");
        System.out.println(loadPrivateKey());

        apkSign();
    }

}