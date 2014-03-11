package ru.bserg.examples; 

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.URL;
import java.security.KeyStore;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;


public class NtlmSslConnect {
	static String URL = "https://host/path";
	static String USER = "username";
	static String PASS = "password";
	static String DOMAIN = "DOMAIN";
	static String JKS_PATH = "file.jks";
	static String JKS_PASS = "file_password";
	
	public static void main(String[] args) throws Exception {
		// Retry count
		System.setProperty("http.maxRedirects", "20");
		
		// Request to host with NTLM
		System.out.println(getResponse());
	}
	
	public static String getResponse() throws Exception {	

		// JDK API AUTH
	    Authenticator.setDefault(new Authenticator() {
	        @Override
	        public PasswordAuthentication getPasswordAuthentication() {
	            System.out.println(getRequestingScheme() + " authentication");
	             // Remember to include the NT domain in the username
	            return new PasswordAuthentication(DOMAIN + "\\" + USER, PASS.toCharArray());
	        }
	    });
	    
	    //SSL support & keystore
	    KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream(JKS_PATH), JKS_PASS.toCharArray());
        
        SSLContext context = SSLContext.getInstance("TLS");
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);
        X509TrustManager defaultTrustManager = (X509TrustManager)tmf.getTrustManagers()[0];
        context.init(null, new TrustManager[] {defaultTrustManager}, null);
        SSLSocketFactory factory = context.getSocketFactory();
        HttpsURLConnection.setDefaultSSLSocketFactory(factory);
	    
        // Url connection
	    URL urlRequest = new URL(URL);
	    HttpsURLConnection conn = (HttpsURLConnection) urlRequest.openConnection();
	    conn.setDoOutput(true);
	    conn.setDoInput(true);
	    conn.setRequestMethod("GET");
	 
	    // Write response to console
	    StringBuilder response = new StringBuilder();
	    InputStream stream = conn.getInputStream();
	    BufferedReader in = new BufferedReader(new InputStreamReader(stream));
	    String str = null;
	    while ((str = in.readLine()) != null) {
	        response.append(str);
	    }
	    in.close();
	    
	    return response.toString();
	}

}
