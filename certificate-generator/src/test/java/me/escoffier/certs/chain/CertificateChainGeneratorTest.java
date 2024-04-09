package me.escoffier.certs.chain;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClientResponse;
import io.vertx.core.http.HttpServer;
import io.vertx.core.net.PemKeyCertOptions;
import io.vertx.core.net.PemTrustOptions;
import io.vertx.core.net.TrustOptions;
import me.escoffier.certs.VertxHttpHelper;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLHandshakeException;
import java.io.File;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CertificateChainGeneratorTest {

    private static Vertx vertx;

    @BeforeAll
    static void initVertx() {
        vertx = Vertx.vertx();
    }

    @AfterAll
    static void closeVertx() {
        vertx.close().toCompletionStage().toCompletableFuture().join();
    }


    @Test
    void testGenerateCertificateChainGeneration() throws Exception {
        File dir = new File("target/chain");
        CertificateChainGenerator generator = new CertificateChainGenerator(dir)
                .withCN("my-app");
        generator.generate();

        // Verify files
        File rootCertificate = new File(dir, "root.crt");
        File rootKey = new File(dir, "root.key");
        File intermediateCertificate = new File(dir, "intermediate.crt");
        File intermediateKey = new File(dir, "intermediate.key");
        File leafCertificate = new File(dir, "my-app.crt");
        File leafKey = new File(dir, "my-app.key");

        assertThat(rootCertificate).isFile();
        assertThat(rootKey).isFile();
        assertThat(intermediateCertificate).isFile();
        assertThat(intermediateKey).isFile();
        assertThat(leafCertificate).isFile();
        assertThat(leafKey).isFile();

        // Verify interactions
        PemKeyCertOptions serverKS = new PemKeyCertOptions()
                .setKeyPath(leafKey.getAbsolutePath())
                .setCertPath(leafCertificate.getAbsolutePath());

        TrustOptions clientTS = new PemTrustOptions()
                .addCertPath(rootCertificate.getAbsolutePath());

        HttpServer server = VertxHttpHelper.createHttpServer(vertx, serverKS);
        HttpClientResponse response = VertxHttpHelper.createHttpClientAndInvoke(vertx, server, clientTS);
        assertThat(response.statusCode()).isEqualTo(200);

    }

    @Test
    void testWithIntermediateInTS() throws Exception {
        File dir = new File("target/chain");
        CertificateChainGenerator generator = new CertificateChainGenerator(dir)
                .withCN("my-app");
        generator.generate();

        File intermediateCertificate = new File(dir, "intermediate.crt");
        File leafCertificate = new File(dir, "my-app.crt");
        File leafKey = new File(dir, "my-app.key");

        PemKeyCertOptions serverKS = new PemKeyCertOptions()
                .setKeyPath(leafKey.getAbsolutePath())
                .setCertPath(leafCertificate.getAbsolutePath());

        TrustOptions clientTS = new PemTrustOptions()
                .addCertPath(intermediateCertificate.getAbsolutePath());

        HttpServer server = VertxHttpHelper.createHttpServer(vertx, serverKS);
        HttpClientResponse response = VertxHttpHelper.createHttpClientAndInvoke(vertx, server, clientTS);
        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Test
    void testWithExposingTheIntermediate() throws Exception {
        File dir = new File("target/chain");
        CertificateChainGenerator generator = new CertificateChainGenerator(dir)
                .withCN("my-app");
        generator.generate();

        File intermediateCertificate = new File(dir, "intermediate.crt");
        File intermediateKey = new File(dir, "intermediate.key");
        File rootCertificate = new File(dir, "root.crt");


        PemKeyCertOptions serverKS = new PemKeyCertOptions()
                .setKeyPath(intermediateKey.getAbsolutePath())
                .setCertPath(intermediateCertificate.getAbsolutePath());

        TrustOptions clientTS = new PemTrustOptions()
                .addCertPath(rootCertificate.getAbsolutePath());

        HttpServer server = VertxHttpHelper.createHttpServer(vertx, serverKS);
        assertThatThrownBy(() -> VertxHttpHelper.createHttpClientAndInvoke(vertx, server, clientTS))
        .hasCauseInstanceOf(SSLHandshakeException.class); // The intermediate is trusted BUT the cn does not match

        var response = VertxHttpHelper.createHttpClientAndInvoke(vertx, server, clientTS, false);
        assertThat(response.statusCode()).isEqualTo(200);
    }

}