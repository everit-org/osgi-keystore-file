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
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public final class KeyStoreUtil {

    public static void createKeyStore(final Provider provider, final String keyStoreType,
            final String keyStoreLocation, final String keyStorePassword, final String signatureAlgorithm,
            final String privateKeyAlias, final PrivateKey privateKey, final String privateKeyPassword,
            final String publicKeyAlias, final PublicKey publicKey) {
        try (OutputStream fos = new FileOutputStream(keyStoreLocation)) {
            KeyStore ks = KeyStore.getInstance(keyStoreType, provider);
            ks.load(null, null);
            Certificate[] certificateChain = {
                    KeyStoreUtil.generateCertificate(privateKey, publicKey, signatureAlgorithm)
            };
            ks.setKeyEntry(privateKeyAlias, privateKey, privateKeyPassword.toCharArray(), certificateChain);
            ks.setCertificateEntry(publicKeyAlias, certificateChain[0]);
            ks.store(fos, keyStorePassword.toCharArray());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static Certificate generateCertificate(final PrivateKey privateKey, final PublicKey publicKey,
            final String signatureAlgorithm) throws Exception {
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
        v3CertGen.setPublicKey(publicKey);
        v3CertGen.setSignatureAlgorithm(signatureAlgorithm);
        return v3CertGen.generateX509Certificate(privateKey);
    }

    public static KeyPair generateKeyPair(final Provider provider, final String keyPairAlgorithm,
            final String secureAlgorithm) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyPairAlgorithm, provider);
            SecureRandom secureRandom = SecureRandom.getInstance(secureAlgorithm);
            keyPairGenerator.initialize(1024, secureRandom);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            return keyPair;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private KeyStoreUtil() {
    }

}
