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
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
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
import org.everit.osgi.service.javasecurity.JavaSecurityFactory;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.cm.ConfigurationException;

/**
 * A factory component that registers an initialized {@link KeyStore} as an OSGi service with the given properties.
 */
@Component(metatype = true, configurationFactory = true, policy = ConfigurationPolicy.REQUIRE)
@Properties({
        @Property(name = PropertyName.JAVA_SECURITY_FACTORY_TARGET),
        @Property(name = PropertyName.KEY_STORE_URL),
        @Property(name = PropertyName.KEY_STORE_TYPE),
        @Property(name = PropertyName.KEY_STORE_PASSWORD, passwordValue = "")
})
public class FileBasedKeyStoreComponent {

    /**
     * A {@link JavaSecurityFactory} used to create the {@link KeyStore}.
     */
    @Reference(bind = "bindJavaSecurityFactory", unbind = "unbindJavaSecurityFactory")
    private JavaSecurityFactory javaSecurityFactory;

    /**
     * The reference of the service registration.
     */
    private ServiceRegistration<KeyStore> keyStoreSR;

    /**
     * The properties of the {@link #javaSecurityFactory} service.
     */
    private Map<String, Object> javaSecurityFactoryProperties;

    /**
     * The provider of the {@link KeyStore}.
     */
    private Provider provider;

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
            throw new ConfigurationException(null, "failed to load the keystore", e);
        }
        try (InputStream inputStream = url.openStream()) {
            keyStore = javaSecurityFactory.createKeyStore(keyStoreType, provider);
            keyStore.load(inputStream, keyStorePasswordChars);
        } catch (NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new ConfigurationException(null, "failed to load the keystore", e);
        }

        Hashtable<String, Object> serviceProperties =
                createKeyStoreServiceProperties(componentProperties, keyStoreUrl, keyStoreType);
        keyStoreSR = context.registerService(KeyStore.class, keyStore, serviceProperties);
    }

    /**
     * Binds a {@link JavaSecurityFactory} to this component and creates the provider.
     * 
     * @param factory
     *            a {@link JavaSecurityFactory} to bind
     * @param serviceProperties
     *            the service properties of the {@link JavaSecurityFactory}
     */
    public void bindJavaSecurityFactory(final JavaSecurityFactory factory,
            final Map<String, Object> serviceProperties) {
        javaSecurityFactory = factory;
        javaSecurityFactoryProperties = serviceProperties;
        provider = javaSecurityFactory.createProvider();
        Security.addProvider(provider);
    }

    private Hashtable<String, Object> createKeyStoreServiceProperties(final Map<String, Object> componentProperties,
            final String keyStoreLocation, final String keyStoreType) {
        Hashtable<String, Object> serviceProperties = new Hashtable<>();
        serviceProperties.putAll(javaSecurityFactoryProperties);
        serviceProperties.remove(Constants.SERVICE_ID);
        serviceProperties.put("javaSecurityFactory." + Constants.SERVICE_ID,
                javaSecurityFactoryProperties.get(Constants.SERVICE_ID));
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

    /**
     * Unbinds a {@link JavaSecurityFactory} from this component.
     * 
     * @param factory
     *            a {@link JavaSecurityFactory} to unbind
     */
    public void unbindJavaSecurityFactory(final JavaSecurityFactory factory) {
        javaSecurityFactory = null;
        Security.removeProvider(provider.getName());
        provider = null;
    }

}
