package ru.bserg.examples.auth;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyStore;

import javax.net.ssl.SSLContext;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.NTCredentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.auth.BasicSchemeFactory;
import org.apache.http.impl.auth.DigestSchemeFactory;
import org.apache.http.impl.auth.KerberosSchemeFactory;
import org.apache.http.impl.auth.NTLMScheme;
import org.apache.http.impl.auth.NTLMSchemeFactory;
import org.apache.http.impl.auth.SPNegoSchemeFactory;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

public class TestApacheHttpClient4 {

	public static void main(String[] args) throws Exception {
		/**
		 * Config Kerberos auth
		 * 
		 * @see TestHttpURLConnection
		 */
		System.setProperty("java.security.krb5.conf", "krb5.conf");
		System.setProperty("java.security.auth.login.config", "login.conf");
		System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");

		/**
		 * Config debug output for Apache HttpClient
		 * https://hc.apache.org/httpcomponents-client-4.3.x/logging.html
		 */
		System.setProperty("sun.security.krb5.debug", "true");
		System.setProperty("org.apache.commons.logging.Log",
				"org.apache.commons.logging.impl.SimpleLog");
		System.setProperty("org.apache.commons.logging.simplelog.showdatetime",	"true");
		System.setProperty("org.apache.commons.logging.simplelog.log.httpclient.wire", "debug");
		System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.commons.httpclient", "debug");

		/**
		 * Request to host with NTLM or Kerberos Apache HttpClient4 support both
		 * protocols
		 * https://hc.apache.org/httpcomponents-client-4.3.x/examples.html] see
		 * Client authentication example
		 */
		System.out.println(getResponse(true));
	}

	static String getResponse(boolean useSsl) throws Exception {

		/**
		 * Config authScheme HttpClient support jdk NTLM engine and JCIFS as
		 * alternative
		 * https://hc.apache.org/httpcomponents-client-4.3.x/ntlm.html
		 */
		Registry<AuthSchemeProvider> authSchemeRegistry = RegistryBuilder
				.<AuthSchemeProvider> create()
				.register(AuthSchemes.NTLM, new NTLMSchemeFactory())
				/** As alternative JCIFS implementation */
				// .register(AuthSchemes.NTLM, new JCIFSNTLMSchemeFactory())
				.register(AuthSchemes.BASIC, new BasicSchemeFactory())
				.register(AuthSchemes.DIGEST, new DigestSchemeFactory())
				/**
				 * For Kerberos. stripPort must be true! Otherwise, sname in
				 * request to Kerberos server (KDC) will be like HTTP/host:PORT
				 */
				.register(AuthSchemes.SPNEGO, new SPNegoSchemeFactory(true))
				.register(AuthSchemes.KERBEROS, new KerberosSchemeFactory(true))
				.build();

		CloseableHttpClient httpclient = null;
		
		if (useSsl) {
			KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
			FileInputStream instream = new FileInputStream(new File(Constants.JKS_PATH));
			try {
				trustStore.load(instream, Constants.JKS_PASS.toCharArray());
			} finally {
				instream.close();
			}

			// Trust own CA and all self-signed certs
			SSLContext sslcontext = SSLContexts.custom()
					.loadTrustMaterial(trustStore, new TrustSelfSignedStrategy())
					.build();
			// Allow TLS protocol
			SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcontext);
			
			// Create client with custom SSLFactory and auth scheme
			httpclient = HttpClients.custom()
					.setDefaultAuthSchemeRegistry(authSchemeRegistry)
					.setSSLSocketFactory(sslsf)
					.build();
		} else {
			httpclient = HttpClients.custom()
					.setDefaultAuthSchemeRegistry(authSchemeRegistry)
					.build();
		}
		
		

		CredentialsProvider credsProvider = new BasicCredentialsProvider();
		// Apache implementation of windows credentials
		credsProvider.setCredentials(AuthScope.ANY, new NTCredentials(Constants.USER, Constants.PASS, "", Constants.DOMAIN));
		// credsProvider.setCredentials(AuthScope.ANY,
		// new UsernamePasswordCredentials(Constants.DOMAIN + "\\" + Constants.USER, Constants.PASS));

		HttpHost target = new HttpHost(Constants.HOST, Constants.PORT, Constants.SCHEMA);

		// Make sure the same context is used to execute logically related
		// requests
		HttpClientContext context = HttpClientContext.create();
		context.setCredentialsProvider(credsProvider);

		// Execute get
		HttpGet httpget = new HttpGet(Constants.PATH);
		CloseableHttpResponse response1 = httpclient.execute(target, httpget, context);
		try {
			HttpEntity entity1 = response1.getEntity();
			StringBuilder response = new StringBuilder();
			InputStream stream = entity1.getContent();
			BufferedReader in = new BufferedReader(new InputStreamReader(stream, Constants.ENCODING));
			String str = null;
			while ((str = in.readLine()) != null) {
				response.append(str);
			}
			in.close();

			return response.toString();
		} finally {
			response1.close();
		}
	}
}