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

/**
 * Property names of {@link FileBasedKeyStoreComponent}.
 */
public final class PropertyName {
    /**
     * The property name of the provider target filter.
     */
    public static final String PROVIDER_TARGET = "provider.target";
    /**
     * The property name of the keystore URL.
     */
    public static final String KEY_STORE_URL = "keyStoreUrl";
    /**
     * The property name of the keystore type.
     */
    public static final String KEY_STORE_TYPE = "keyStoreType";
    /**
     * The property name of the keystore password.
     */
    public static final String KEY_STORE_PASSWORD = "keyStorePassword";

    private PropertyName() {
    }

}
