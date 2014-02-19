package org.everit.osgi.keystore.file;

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

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.util.Hashtable;
import java.util.Map;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.ConfigurationPolicy;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.cm.ConfigurationException;

/**
 * A factory component that registers an initialized {@link KeyStore} as an OSGi service with the given properties.
 */
@Component(metatype = true, configurationFactory = true, policy = ConfigurationPolicy.REQUIRE)
@Properties({
        @Property(name = PropertyName.PROVIDER_TARGET),
        @Property(name = PropertyName.KEY_STORE_URL),
        @Property(name = PropertyName.KEY_STORE_TYPE),
        @Property(name = PropertyName.KEY_STORE_PASSWORD, passwordValue = "")
})
public class FileBasedKeyStoreComponent {

    @Reference(bind = "bindProvider", unbind = "unbindProvider")
    private Provider provider;

    /**
     * The properties of the {@link #provider} service.
     */
    private Map<String, Object> providerServiceProperties;

    /**
     * The reference of the service registration.
     */
    private ServiceRegistration<KeyStore> keyStoreSR;

    /**
     * The activation method of the component. It registers the {@link KeyStore} as an OSGi service.
     * 
     * @param context
     *            the context of the bundle
     * @param componentProperties
     *            the properties of the component
     * @throws ConfigurationException
     *             if the required configuration properties are not defined or if the initialization of the
     *             {@link KeyStore} fails
     */
    @Activate
    public void activate(final BundleContext context, final Map<String, Object> componentProperties)
            throws ConfigurationException {
        String keyStoreUrl = getStringProperty(componentProperties, PropertyName.KEY_STORE_URL);
        String keyStoreType = getStringProperty(componentProperties, PropertyName.KEY_STORE_TYPE);
        String keyStorePassword = getStringProperty(componentProperties, PropertyName.KEY_STORE_PASSWORD);

        char[] keyStorePasswordChars = keyStorePassword.toCharArray();
        KeyStore keyStore;
        URL url;
        try {
            url = new URL(keyStoreUrl);
        } catch (MalformedURLException e) {
            throw new ConfigurationException(null, "failed to load the keystore from URL [" + keyStoreUrl + "]", e);
        }
        try (InputStream inputStream = url.openStream()) {
            keyStore = KeyStore.getInstance(keyStoreType, provider);
            keyStore.load(inputStream, keyStorePasswordChars);
        } catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException e) {
            throw new ConfigurationException(null, "failed to load the keystore from URL [" + keyStoreUrl + "]", e);
        }

        Hashtable<String, Object> serviceProperties =
                createKeyStoreServiceProperties(componentProperties, keyStoreUrl, keyStoreType);
        keyStoreSR = context.registerService(KeyStore.class, keyStore, serviceProperties);
    }

    public void bindProvider(final Provider provider, final Map<String, Object> providerServiceProperties) {
        this.provider = provider;
        this.providerServiceProperties = providerServiceProperties;
    }

    private Hashtable<String, Object> createKeyStoreServiceProperties(final Map<String, Object> componentProperties,
            final String keyStoreLocation, final String keyStoreType) {
        Hashtable<String, Object> serviceProperties = new Hashtable<>();
        serviceProperties.putAll(providerServiceProperties);
        serviceProperties.remove(Constants.SERVICE_ID);
        serviceProperties.put("provider." + Constants.SERVICE_ID, providerServiceProperties.get(Constants.SERVICE_ID));
        serviceProperties.put(Constants.SERVICE_PID, componentProperties.get(Constants.SERVICE_PID));
        serviceProperties.put(PropertyName.KEY_STORE_URL, keyStoreLocation);
        serviceProperties.put(PropertyName.KEY_STORE_TYPE, keyStoreType);
        return serviceProperties;
    }

    /**
     * The deactivation method of the component. It unregisters the service registration of the {@link KeyStore}.
     */
    @Deactivate
    public void deactivate() {
        if (keyStoreSR != null) {
            keyStoreSR.unregister();
            keyStoreSR = null;
        }
    }

    private String getStringProperty(final Map<String, Object> componentProperties, final String propertyName)
            throws ConfigurationException {
        Object value = componentProperties.get(propertyName);
        if (value == null) {
            throw new ConfigurationException(propertyName, "property not defined");
        }
        return String.valueOf(value);
    }

    public void unbindProvider(final Provider provider) {
        this.provider = null;
    }

}
