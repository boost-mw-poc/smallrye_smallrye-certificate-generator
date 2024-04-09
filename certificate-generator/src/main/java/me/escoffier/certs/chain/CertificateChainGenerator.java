package me.escoffier.certs.chain;

import me.escoffier.certs.CertificateUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.File;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

public class CertificateChainGenerator {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private String cn = "localhost";

    private List<String> sans = List.of("DNS:localhost");

    private File baseDir; // Mandatory

    public CertificateChainGenerator(File baseDir) {
        this.baseDir = baseDir;
        if (!baseDir.isDirectory()) {
            baseDir.mkdirs();
        }
    }

    /**
     * Configure the common name of the "leaf" certificate.
     *
     * @param cn the common name, by default `localhost`
     * @return the current generator instance
     */
    public CertificateChainGenerator withCN(String cn) {
        this.cn = cn;
        return this;
    }

    /**
     * Configure the Subject Alternative Names of the "leaf" certificate.
     *
     * @param san the list of SAN, by default `DNS:localhost`
     * @return the current generator instance
     */
    public CertificateChainGenerator withSAN(List<String> san) {
        this.sans = san;
        return this;
    }

    public void generate() throws Exception {

        // Generate root certificate
        var rootKeyPair = generateKeyPair();
        var rootCertificate = generateRootCertificate(rootKeyPair);

        // Generate intermediary certificate
        var intermediaryKeyPair = generateKeyPair();
        var intermediaryCertificate = generateIntermediaryCertificate(intermediaryKeyPair, rootKeyPair, rootCertificate);

        // Generate leaf certificate
        var leafKeyPair = generateKeyPair();
        var leafCertificate = generateLeafCertificate(leafKeyPair, intermediaryKeyPair, intermediaryCertificate);

        // Write the certificates to files
        // root.crt, root.key, intermediary.crt, intermediary.key, cn.crt, cn.key
        CertificateUtils.writeCertificateToPEM(rootCertificate, new File(baseDir, "root.crt"));
        CertificateUtils.writePrivateKeyToPem(rootKeyPair.getPrivate(), new File(baseDir, "root.key"));

        CertificateUtils.writeCertificateToPEM(intermediaryCertificate, new File(baseDir, "intermediate.crt"));
        CertificateUtils.writePrivateKeyToPem(intermediaryKeyPair.getPrivate(), new File(baseDir, "intermediate.key"));

        CertificateUtils.writeCertificateToPEM(leafCertificate, new File(baseDir, cn + ".crt"), intermediaryCertificate);
        CertificateUtils.writePrivateKeyToPem(leafKeyPair.getPrivate(), new File(baseDir, cn + ".key"));
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(2048, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    private X509Certificate generateRootCertificate(KeyPair rootKeyPair) throws CertIOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException {
        var keyInfo = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(rootKeyPair.getPublic().getEncoded()));
        var issuer = new X500Name("CN=quarkus-root,O=Quarkus Development");
        var subject = new X500Name("CN=root");
        var yesterday = new Date(System.currentTimeMillis() - 86400000);
        var oneYear = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000); // 1 year
        X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(System.currentTimeMillis()),
                yesterday,
                oneYear,
                subject,
                keyInfo);

        certGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));
        certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        certGen.addExtension(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(rootKeyPair.getPublic()));

        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
        ContentSigner signer = contentSignerBuilder.build(rootKeyPair.getPrivate());
        X509CertificateHolder holder = certGen.build(signer);
        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    private X509Certificate generateIntermediaryCertificate(KeyPair intermediaryKeyPair, KeyPair rootKeyPair, X509Certificate rootCertificate) throws NoSuchAlgorithmException, CertIOException, OperatorCreationException, CertificateException {
        var keyInfo = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(intermediaryKeyPair.getPublic().getEncoded()));
        var yesterday = new Date(System.currentTimeMillis() - 86400000);
        var oneYear = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000); // 1 year
        X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(
                new X500Name(rootCertificate.getSubjectX500Principal().getName()),
                BigInteger.valueOf(System.currentTimeMillis()),
                yesterday,
                oneYear,
                new X500Name("CN=intermediary"),
                keyInfo
        );

        certGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature));
        certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        certGen.addExtension(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(intermediaryKeyPair.getPublic()));

        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
        ContentSigner contentSigner = contentSignerBuilder.build(rootKeyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(certGen.build(contentSigner));
    }

    private X509Certificate generateLeafCertificate(KeyPair leafKeyPair, KeyPair intermediaryKeyPair, X509Certificate intermediaryCertificate) throws NoSuchAlgorithmException, CertIOException, OperatorCreationException, CertificateException {
        var keyInfo = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(leafKeyPair.getPublic().getEncoded()));
        var before = Instant.now().minus(2, ChronoUnit.DAYS);
        var after = Instant.now().plus(2, ChronoUnit.DAYS);

        X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(
                new X500Name(intermediaryCertificate.getSubjectX500Principal().getName()),
                BigInteger.valueOf(System.currentTimeMillis()),
                new java.util.Date(before.toEpochMilli()),
                new java.util.Date(after.toEpochMilli()),
                new X500Name("CN=" + cn),
                keyInfo
        );

        certGen.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.keyAgreement | KeyUsage.nonRepudiation));
        certGen.addExtension(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(leafKeyPair.getPublic()));

        DERSequence subjectAlternativeNames =
                new DERSequence(sans.stream().map(s -> {
                    if (s.startsWith("DNS:")) {
                        return new GeneralName(GeneralName.dNSName, s.substring(4));
                    } else if (s.startsWith("IP:")) {
                        return new GeneralName(GeneralName.iPAddress, s.substring(3));
                    } else {
                        return new GeneralName(GeneralName.dNSName, s);
                    }
                }).toArray(ASN1Encodable[]::new));
        certGen.addExtension(Extension.subjectAlternativeName, false, subjectAlternativeNames);

        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
        ContentSigner contentSigner = contentSignerBuilder.build(intermediaryKeyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(certGen.build(contentSigner));
    }


}
