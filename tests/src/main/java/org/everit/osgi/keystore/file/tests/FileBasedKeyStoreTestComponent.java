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

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.ConfigurationPolicy;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.Service;
import org.junit.Assert;
import org.junit.Test;

@Component(metatype = true, policy = ConfigurationPolicy.REQUIRE)
@Properties({
        @Property(name = "eosgi.testEngine", value = "junit4"),
        @Property(name = "eosgi.testId", value = "FileBasedKeyStoreTestComponent"),
        @Property(name = "keyStore.target") })
@Service(value = FileBasedKeyStoreTestComponent.class)
public class FileBasedKeyStoreTestComponent {

    private final KeyPair expectedKeyPair = ConfigurationInitComponent.KEY_PAIR;

    @Reference
    private KeyStore keyStore;

    @Activate
    public void activate() {
    }

    public void bindKeyStore(final KeyStore keyStore) {
        this.keyStore = keyStore;
    }

    @Test
    public void testKeyStoreInitialization() throws UnrecoverableKeyException, KeyStoreException,
            NoSuchAlgorithmException {
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(ConfigurationInitComponent.ALIAS,
                ConfigurationInitComponent.PRIVATE_KEY_PASSWORD);
        Assert.assertNotNull(privateKey);
        Assert.assertArrayEquals(expectedKeyPair.getPrivate().getEncoded(), privateKey.getEncoded());
        Certificate certificate = keyStore.getCertificate(ConfigurationInitComponent.ALIAS);
        Assert.assertNotNull(certificate);
        Assert.assertArrayEquals(expectedKeyPair.getPublic().getEncoded(), certificate.getPublicKey().getEncoded());
    }

}
