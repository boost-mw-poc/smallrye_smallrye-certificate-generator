package io.smallrye.certs.junit5;

import io.smallrye.certs.Format;

public @interface Certificate {

    /**
     * Sets the name of the certificate.
     */
    String name();

    /**
     * Sets the formats of the certificate, are supported: JKS, PEM and PKCS12.
     */
    Format[] formats();

    /**
     * Sets the password of the certificate if needed.
     */
    String password() default "";

    /**
     * Sets the duration of the certificate in days.
     */
    int duration() default 2;

    /**
     * Sets the CN (common name) of the certificate.
     */
    String cn() default "localhost";

    /**
     * Sets whether the certificate is a client certificate. This is useful for mutual TLS.
     */
    boolean client() default false;

    Alias[] aliases() default {};

    /**
     * Sets the subject alternative names of the certificate.
     * Must follow the format "DNS:example.com", or "IP:127.0.0.1".
     */
    String[] subjectAlternativeNames() default {};

}
