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

import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.Provider;
import java.util.Dictionary;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Set;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.Service;
import org.everit.osgi.keystore.file.FileBasedKeyStoreComponent;
import org.everit.osgi.keystore.file.PropertyName;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;

@Component(immediate = true)
@Properties({
        @Property(name = "provider.target", value = "(providerName=BC)")
})
@Service(value = ConfigurationInitComponent.class)
public class ConfigurationInitComponent {

    private static final String KEY_STORE_TYPE = "BKS";

    private static final String PROVIDER_TARGET_FILTER = "(providerName=BC)";

    private static final String KEY_STORE_PASSWORD = "testKeyStorePassword";

    public static final String PRIVATE_KEY_ALIAS = "test-private-key-alias";

    public static final String PRIVATE_KEY_PASSWORD = "testPrivateKeyPassword";

    public static final String PUBLIC_KEY_ALIAS = "test-public-key-alias";

    public static KeyPair KEY_PAIR;

    @Reference(bind = "bindConfigAdmin")
    private ConfigurationAdmin configAdmin;

    @Reference(bind = "bindProvider")
    private Provider provider;

    private File keyStoreFile;

    private Set<String> pids = new HashSet<>();

    @Activate
    public void activate(final BundleContext bundleContext) throws Exception {
        keyStoreFile = File.createTempFile("test-key-store", "");
        String keyStoreLocation = keyStoreFile.getAbsolutePath();

        KEY_PAIR = KeyStoreUtil.generateKeyPair(provider, "RSA", "SHA1PRNG");
        KeyStoreUtil.createKeyStore(provider, KEY_STORE_TYPE, keyStoreLocation, KEY_STORE_PASSWORD,
                "SHA1WITHRSA", PRIVATE_KEY_ALIAS, KEY_PAIR.getPrivate(), PRIVATE_KEY_PASSWORD, PUBLIC_KEY_ALIAS,
                KEY_PAIR.getPublic());

        String keyStoreUrl = keyStoreFile.toURI().toURL().toString();

        deleteConfigurations();

        Dictionary<String, String> keyStoreProps = new Hashtable<>();
        keyStoreProps.put(PropertyName.PROVIDER_TARGET, PROVIDER_TARGET_FILTER);
        keyStoreProps.put(PropertyName.KEY_STORE_URL, keyStoreUrl);
        keyStoreProps.put(PropertyName.KEY_STORE_TYPE, KEY_STORE_TYPE);
        keyStoreProps.put(PropertyName.KEY_STORE_PASSWORD, KEY_STORE_PASSWORD);
        String keyStorePid = getOrCreateConfiguration(FileBasedKeyStoreComponent.class.getName(), keyStoreProps);

        Dictionary<String, String> keyStoreTestProps = new Hashtable<>();
        keyStoreTestProps.put("keyStore.target", "(" + Constants.SERVICE_PID + "=" + keyStorePid + ")");
        String keyStoreTestPid = getOrCreateConfiguration(FileBasedKeyStoreTestComponent.class.getName(),
                keyStoreTestProps);

        pids.add(keyStorePid);
        pids.add(keyStoreTestPid);

    }

    public void bindConfigAdmin(final ConfigurationAdmin configAdmin) {
        this.configAdmin = configAdmin;
    }

    public void bindProvider(final Provider provider) {
        this.provider = provider;
    }

    @Deactivate
    public void deactivate() throws Exception {
        if (!keyStoreFile.delete()) {
            keyStoreFile.deleteOnExit();
        }
        deleteConfigurations();
    }

    private void deleteConfigurations() throws IOException, InvalidSyntaxException {
        for (String pid : pids) {
            Configuration[] configurations =
                    configAdmin.listConfigurations("(" + Constants.SERVICE_PID + "=" + pid + ")");
            if (configurations != null) {
                for (Configuration configuration : configurations) {
                    configuration.delete();
                }
            }
        }
        pids.clear();
    }

    private String getOrCreateConfiguration(final String factoryPid, final Dictionary<String, String> props)
            throws IOException, InvalidSyntaxException {
        Configuration[] configurations = configAdmin.listConfigurations("(service.factoryPid=" + factoryPid + ")");
        if ((configurations != null) && (configurations.length > 0)) {
            return configurations[0].getPid();
        }
        Configuration configuration = configAdmin.createFactoryConfiguration(factoryPid, null);
        configuration.update(props);
        return configuration.getPid();
    }

}
