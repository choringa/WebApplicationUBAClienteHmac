/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package webapplicationubacliente;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Applicación cliente desarrollada para TTFFE Maestria Seguridad Informática UBA
 * @author DA.
 */
public class WebApplicationUBACliente {

    //Constantes
    private final static String DATE_FORMAT = "EEE, d MMM yyyy HH:mm:ss z";
    private final static String HMAC_SHA256_ALGORITHM = "HmacSHA256";
    private final static String SECRET_KEY = "ubaWS.HMAC";
    private final static String DATA = "WS Seguro HMAC Test";
    
    private final static String ADMIN_USERNAME = "administrador";
    private final static String ADMIN_PASS = "adminp4ss";
    
    private final static String BASE_URL = "http://localhost:8080/WebApplicationUBASegura/seguraWS/";
    private final static String WS_RECURSO_USUARIOS_VERIFICAR_HMAC = "ws.usuarios/verificarHmac";

    private static HttpURLConnection con;

    /**
     * Metodo encargado de generar el HMAC
     * @param data el texto plano que es la información con la que se va a crear el hmac
     * @return un string con el hmac generado
     */
    public static String calculateHMAC(String data) {
        try {
            Mac sha256_HMAC = Mac.getInstance(HMAC_SHA256_ALGORITHM);
            SecretKeySpec secret_key = new SecretKeySpec(SECRET_KEY.getBytes("UTF-8"), HMAC_SHA256_ALGORITHM);
            sha256_HMAC.init(secret_key);
            byte[] rawHmac = sha256_HMAC.doFinal(data.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(rawHmac);
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException | InvalidKeyException ex) {
            Logger.getLogger(WebApplicationUBACliente.class.getName()).log(Level.SEVERE, null, ex);
            System.out.println("ERROR: --->" + ex.getLocalizedMessage());
            return "";
        }
    }
    
    /**
     * Metodo encargado hacer la peticion GET al WS Seguro
     * @throws IOException por si explota en algun punto de la conexion
     */
    public static void getVerificarHMAC() throws IOException {
        String userCredentials = ADMIN_USERNAME + ":" + ADMIN_PASS;
        String basicAuth = "Basic " + new String(Base64.getEncoder().encode(userCredentials.getBytes()));
        System.out.println("Parametro de autenticación: " + basicAuth);
        String currentDate = new SimpleDateFormat(DATE_FORMAT).format(new Date(System.currentTimeMillis()));
        System.out.println("Inicio de creacion de digest:" + currentDate);
        String digest = calculateHMAC(DATA);
        System.out.println("Digest creado con llave: " + SECRET_KEY + " e informacion: " + DATA + " ----> " + digest);
        currentDate = new SimpleDateFormat(DATE_FORMAT).format(new Date(System.currentTimeMillis()));
        System.out.println("Fin de creacion de digest; envío de solicitud:" + currentDate);
        try {

            URL myurl = new URL(BASE_URL + WS_RECURSO_USUARIOS_VERIFICAR_HMAC);
            con = (HttpURLConnection) myurl.openConnection();
            con.setRequestMethod("GET");
            con.setRequestProperty("Authorization", basicAuth);
            con.setRequestProperty("hmac", digest);
            con.setRequestProperty("data", DATA);
            
            StringBuilder content;
            InputStream is = con.getInputStream();
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(is));

            String line;
            content = new StringBuilder();

            while ((line = in.readLine()) != null) {
                content.append(line);
                content.append(System.lineSeparator());
            }

            System.out.println("\nRespuesta WS seguro: \n" + content.toString());
            currentDate = new SimpleDateFormat(DATE_FORMAT).format(new Date(System.currentTimeMillis()));
            System.out.println(currentDate);

        }
        catch (IOException ex){
            System.out.println("ERROR---> ex:" + ex.getLocalizedMessage());
            System.out.println("Mensaje--->" + con.getResponseMessage());
            System.out.println("Codigo--->" + con.getResponseCode());
        }
        finally {
            con.disconnect();
        }
    }

    private String calculateMD5(String contentToEncode) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        digest.update(contentToEncode.getBytes());
        String result = new String(Base64.getEncoder().encodeToString(digest.digest()));
        return result;
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        try {
            getVerificarHMAC();
        } catch (Exception ex) {
            Logger.getLogger(WebApplicationUBACliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
