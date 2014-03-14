package ru.bserg.examples.jcifs;

import org.apache.http.auth.AuthScheme;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.impl.auth.NTLMScheme;
import org.apache.http.protocol.HttpContext;

public class JCIFSNTLMSchemeFactory implements AuthSchemeProvider {

    public AuthScheme create(final HttpContext context) {
        return new NTLMScheme(new JCIFSEngine());
    }
}
