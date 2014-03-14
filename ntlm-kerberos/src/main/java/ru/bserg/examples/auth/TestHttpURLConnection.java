package ru.bserg.examples.auth;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.PasswordAuthentication;
import java.net.URL;
import java.security.KeyStore;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class TestHttpURLConnection {

	public static void main(String[] args) throws Exception {
		/** 
		 * Property for kerberos config 
		 * http://web.mit.edu/kerberos/krb5-devel/doc/admin/conf_files/krb5_conf.html
		 * for generate keytab file use kint and ktab util from jdk.
		 * ktab -a <USER> <NAME> generate keytab file in default system location 
		 */ 
		System.setProperty("java.security.krb5.conf", "krb5.conf");
		System.setProperty("java.security.auth.login.config", "login.conf");
		System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");
		
		/** Setting property for Kerberos debug output */
		System.setProperty("sun.security.krb5.debug", "true");

		/** Retry count */
		System.setProperty("http.maxRedirects", "3");

		/** 
		 * Request to host with NTLM or Kerberos 
		 * Java 6 support both protocols. 
		 * http://docs.oracle.com/javase/7/docs/technotes/guides/net/http-auth.html 
		 */
		System.out.println(getResponse(true));
	}

	public static String getResponse(boolean useSsl) throws Exception {

		// JDK API AUTH
		Authenticator.setDefault(new Authenticator() {
			@Override
			public PasswordAuthentication getPasswordAuthentication() {
				System.out.println(getRequestingScheme() + " authentication");
				// Remember to include the NT domain in the username
				return new PasswordAuthentication(Constants.DOMAIN + "\\" + Constants.USER, Constants.PASS.toCharArray());
			}
		});

		// SSL support & keystore
		if (useSsl) {
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new FileInputStream(Constants.JKS_PATH), Constants.JKS_PASS.toCharArray());

			SSLContext context = SSLContext.getInstance("TLS");
			TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init(keyStore);
			X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
			context.init(null, new TrustManager[] { defaultTrustManager }, null);
			SSLSocketFactory factory = context.getSocketFactory();
			HttpsURLConnection.setDefaultSSLSocketFactory(factory);
		}

		// Url connection
		URL urlRequest = new URL(Constants.URL);
		HttpURLConnection conn = (HttpURLConnection) urlRequest.openConnection();
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
