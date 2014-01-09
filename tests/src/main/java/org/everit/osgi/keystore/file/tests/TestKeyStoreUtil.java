package org.everit.osgi.keystore.file.tests;

/*
 * Copyright (c) 2011, Everit Kft.
 *
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301  USA
 */

import java.io.FileOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public final class TestKeyStoreUtil {

    public static void createBCKeyStore(final String keyStoreType,
            final String keyStoreLocation, final String keyStorePassword, final String signatureAlgorithm,
            final String alias, final KeyPair keyPair, final char[] entryPassword) {
        Provider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        try (OutputStream fos = new FileOutputStream(keyStoreLocation)) {
            KeyStore ks = KeyStore.getInstance(keyStoreType, provider);
            ks.load(null, null);
            Certificate[] certificateChain = { TestKeyStoreUtil.generateCertificate(keyPair, signatureAlgorithm) };
            PrivateKey privateKey = keyPair.getPrivate();
            ks.setKeyEntry(alias, privateKey, entryPassword, certificateChain);
            ks.store(fos, keyStorePassword.toCharArray());
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            Security.removeProvider(provider.getName());
        }
    }

    private static Certificate generateCertificate(final KeyPair keyPair, final String signatureAlgorithm)
            throws Exception {
        Calendar calendar = Calendar.getInstance();
        Date notBefore = calendar.getTime();
        calendar.add(Calendar.MINUTE, 1);
        Date notAfter = calendar.getTime();

        X509V3CertificateGenerator v3CertGen = new X509V3CertificateGenerator();
        v3CertGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        v3CertGen.setIssuerDN(new X509Principal("CN=cn, O=o, L=L, ST=il, C=c"));
        v3CertGen.setNotBefore(notBefore);
        v3CertGen.setNotAfter(notAfter);
        v3CertGen.setSubjectDN(new X509Principal("CN=cn, O=o, L=L, ST=il, C=c"));
        v3CertGen.setPublicKey(keyPair.getPublic());
        v3CertGen.setSignatureAlgorithm(signatureAlgorithm);
        return v3CertGen.generateX509Certificate(keyPair.getPrivate());
    }

    public static KeyPair generateKeyPair(final String keyPairAlgorithm, final String secureAlgorithm) {
        Provider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyPairAlgorithm, provider);
            SecureRandom secureRandom = SecureRandom.getInstance(secureAlgorithm);
            keyPairGenerator.initialize(1024, secureRandom);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            return keyPair;
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            Security.removeProvider(provider.getName());
        }
    }

    private TestKeyStoreUtil() {
    }

}
