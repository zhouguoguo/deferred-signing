package com.client;

import org.apache.commons.codec.Charsets;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Properties;

public class SignerClient {
    static String PreSignURL;
    static String PostSignURL;
    public static final String CERT = "src/main/resources/gdca.cer";
    public static final String PFX = "src/main/resources/fy-new2.pfx";
    public static final String PROPERTY = "src/main/resources/key.property";
    public static final String DEST = "results/signed.pdf";
    static String key_password;

    List<String> cookies;

    public static void readProperty(String propertyPath) {
        Properties properties = new Properties();
        try {
            properties.load(new FileInputStream(propertyPath));
            key_password = properties.getProperty("PASSWORD");
            PreSignURL = properties.getProperty("presign-url");
            PostSignURL = properties.getProperty("postsign-url");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public byte[] getHash(String cert) throws IOException {
        URL url = new URL(PreSignURL);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setDoOutput(true);
        conn.setRequestMethod("POST");
        conn.connect();

        // we upload our certificate
        OutputStream os = conn.getOutputStream();
        FileInputStream fis = new FileInputStream(cert);
        int read;
        byte[] data = new byte[256];
        while ((read = fis.read(data, 0, data.length)) != -1) {
            os.write(data, 0, read);
        }
        os.flush();
        os.close();

        // we use cookies to maintain a session
        cookies = conn.getHeaderFields().get("Set-Cookie");

        System.out.println("cookies");
        for (int i=0; i<cookies.size(); i++)
        {
            System.out.println("cookies " + i);
            System.out.println(cookies.get(i));
        }

        // we receive a hash that needs to be signed
        InputStream is = conn.getInputStream();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        while ((read = is.read(data)) != -1) {
            baos.write(data, 0, read);
        }
        is.close();

        byte[] hash = baos.toByteArray();
        return hash;
    }

    public byte[] Sign(byte[] hash, String pfx) throws NoSuchProviderException, KeyStoreException,
            IOException, UnrecoverableKeyException, NoSuchAlgorithmException,
            InvalidKeyException, SignatureException, CertificateException {
        byte[] data = new byte[256];

        Security.addProvider(new BouncyCastleProvider());
        KeyStore ks = KeyStore.getInstance("pkcs12", "BC");
        FileInputStream input = new FileInputStream(pfx);
        char[] kp = key_password.toCharArray();
        ks.load(input, kp);
        String alias = (String) ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, key_password.toCharArray());
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(pk);
        sig.update(hash);
        data = sig.sign();

        return data;
    }

    public void getSignedPDF(byte[] data, String file) throws IOException {
        URL url = new URL(PostSignURL);
        HttpURLConnection conn = (HttpURLConnection)url.openConnection();
        for (String cookie : cookies) {
            conn.addRequestProperty("Cookie", cookie.split(";", 2)[0]);
        }
        conn.setDoOutput(true);
        conn.setRequestMethod("POST");
        conn.connect();

        // we upload the signed bytes
        OutputStream os = conn.getOutputStream();
        os = conn.getOutputStream();
        os.write(data);
        os.flush();
        os.close();

        // we get the signed PDF from server
        InputStream is = conn.getInputStream();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        data = new byte[256*100];
        int read;
        while ((read = is.read(data)) != -1) {
            baos.write(data, 0, read);
        }
        is.close();
        byte[] pdf = baos.toByteArray();
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(pdf);
        fos.close();
    }

    public static void main(String args[])
    {
        readProperty(PROPERTY);
        SignerClient sc = new SignerClient();
        // 1. get hash to be signed from server
        byte[] hash = null;
        try {
            hash = sc.getHash(CERT);
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("base64 hash:\n" + new String(Base64.encode(hash), Charsets.UTF_8));

        // 2. sign hash with private key
        byte[] signature = null;
        try {
            signature = sc.Sign(hash, PFX);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("base64 signed hash:\n" + new String(Base64.encode(signature), Charsets.UTF_8));

        // 3. post signed hash to server and get the signed PDF
        try {
            sc.getSignedPDF(signature, DEST);
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}
