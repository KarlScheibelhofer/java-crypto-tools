package dev.scheibelhofer.crypto.provider;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import org.junit.jupiter.api.Test;

public class TestTLSServer {

    static final Logger LOG = Logger.getLogger(TestTLSServer.class.getName());

    @Test
    public void testTLSServerSocket() throws Exception {
        Security.addProvider(JctProvider.getInstance());
        
        System.setProperty("javax.net.ssl.keyStore", Path.of("src/test/resources/www.doesnotexist.org-EC-keystore.pem").toAbsolutePath().toString());
        System.setProperty("javax.net.ssl.keyStorePassword", "password");
        System.setProperty("javax.net.ssl.keyStoreType", "pem");

        Thread serverThread = new Thread(createTLSServer());
        serverThread.start();

        System.setProperty("javax.net.ssl.trustStore", Path.of("src/test/resources/www.doesnotexist.org-EC-truststore.pem").toAbsolutePath().toString());
        System.setProperty("javax.net.ssl.trustStorePassword", "password");
        System.setProperty("javax.net.ssl.trustStoreType", "pem");
        URL url = new URL("https://localhost:8443/");
        try (BufferedReader responseReader = new BufferedReader(new InputStreamReader(url.openStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = responseReader.readLine()) != null) {
                LOG.log(Level.INFO, "CLIENT " + line);
            }
        }
        
        serverThread.join();
        
        Security.removeProvider(JctProvider.getInstance().getName());
    }

    Runnable createTLSServer() {
        final Runnable serverRunnable = () -> {
            SSLServerSocketFactory ssf = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
            try (ServerSocket ss = ssf.createServerSocket(8443)) {
                LOG.log(Level.INFO, "SERVER listen... ");
                Socket socket = ss.accept();
                LOG.log(Level.INFO, "SERVER accepted incoming connection");
                
                SSLSession session = ((SSLSocket) socket).getSession();
                List<X509Certificate> serverCertChain = Arrays.asList(session.getLocalCertificates()).stream()
                    .filter(X509Certificate.class::isInstance)
                    .map (X509Certificate.class::cast)
                    .collect(Collectors.toList());
                
                StringBuilder sb = new StringBuilder();
                sb.append("Peer Host: " + session.getPeerHost()).append("\r\n");
                sb.append("Cipher-Suite: " + session.getCipherSuite()).append("\r\n");
                sb.append("Protocol: " + session.getProtocol()).append("\r\n");
                X509Certificate serverCert = serverCertChain.get(0);
                sb.append("Server Certificate - Subject: " + serverCert.getSubjectDN())
                  .append(" - Issuer: ").append(serverCert.getIssuerDN())
                  .append(" - Serial: 0x").append(serverCert.getSerialNumber().toString(16))
                  .append("\r\n");
                String body = sb.toString();

                PrintStream out = new PrintStream(socket.getOutputStream());
                out.print("HTTP/1.1 200 OK"); out.print("\r\n");
                out.print("Content-Length: "); out.print(body.length()); out.print("\r\n");
                out.print("Content-Type: text/plain"); out.print("\r\n");
                out.print("\r\n");
                out.print(body);
                
                out.close();
                socket.close();                
            } catch (Exception e) {
                e.printStackTrace();
            }
        };

        return serverRunnable;
    }

}
