// Copyright (C) 2026 MINHAP, Gobierno de España
// This program is licensed and may be used, modified and redistributed under the terms
// of the European Public License (EUPL), either version 1.1 or (at your
// option) any later version as soon as they are approved by the European Commission.

package es.gob.afirma.wsServiceInvoker.crypto;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;

/**
 * Cache shared by the service-invoker handlers for WSS4J Crypto instances.
 *
 * <p>The cache is deliberately limited in size, although a system is not expected
 * to require new objects unless new applications are added. Creation is synchronized
 * so that concurrent requests using the same configuration do not load the keystore
 * repeatedly.</p>
 */
public final class CryptoCache {

    private static final String MERLIN_PROVIDER = "org.apache.ws.security.components.crypto.Merlin";
    private static final int MAX_ENTRIES = 64;

    private static final Map<CryptoKey, Crypto> CACHE = new LinkedHashMap<CryptoKey, Crypto>(16, 0.75f, true) {
        private static final long serialVersionUID = 1L;

        @Override
        protected boolean removeEldestEntry(Map.Entry<CryptoKey, Crypto> eldest) {
            return size() > MAX_ENTRIES;
        }
    };

    private CryptoCache() {
        // Utility class.
    }

    /**
     * Gets a cached Merlin Crypto or creates it if this exact configuration
     * has not been used before.
     *
     * @param keystoreType keystore type.
     * @param keystorePassword keystore password.
     * @param alias certificate/private-key alias.
     * @param aliasPassword alias/private-key password.
     * @param keystoreFile keystore location.
     * @return the reusable Crypto instance.
     * @throws WSSecurityException if the Crypto cannot be created.
     */
    public static synchronized Crypto getCrypto(String keystoreType, String keystorePassword, String alias,
            String aliasPassword, String keystoreFile) throws WSSecurityException {
        CryptoKey key = new CryptoKey(MERLIN_PROVIDER, keystoreType, keystorePassword, alias, aliasPassword,
                keystoreFile);
        Crypto crypto = CACHE.get(key);
        if (crypto == null) {
            Properties properties = new Properties();
            properties.setProperty("org.apache.ws.security.crypto.provider", MERLIN_PROVIDER);
            properties.setProperty("org.apache.ws.security.crypto.merlin.keystore.type", keystoreType);
            properties.setProperty("org.apache.ws.security.crypto.merlin.keystore.password", keystorePassword);
            properties.setProperty("org.apache.ws.security.crypto.merlin.keystore.alias", alias);
            properties.setProperty("org.apache.ws.security.crypto.merlin.alias.password", aliasPassword);
            properties.setProperty("org.apache.ws.security.crypto.merlin.file", keystoreFile);
            crypto = CryptoFactory.getInstance(properties);
            CACHE.put(key, crypto);
        }
        return crypto;
    }

    private static final class CryptoKey {
        private final String provider;
        private final String keystoreType;
        private final String keystorePassword;
        private final String alias;
        private final String aliasPassword;
        private final String keystoreFile;

        CryptoKey(String provider, String keystoreType, String keystorePassword, String alias, String aliasPassword,
                String keystoreFile) {
            this.provider = provider;
            this.keystoreType = keystoreType;
            this.keystorePassword = keystorePassword;
            this.alias = alias;
            this.aliasPassword = aliasPassword;
            this.keystoreFile = keystoreFile;
        }

        @Override
        public int hashCode() {
            return Objects.hash(provider, keystoreType, keystorePassword, alias, aliasPassword, keystoreFile);
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof CryptoKey)) {
                return false;
            }
            CryptoKey other = (CryptoKey) obj;
            return Objects.equals(provider, other.provider)
                    && Objects.equals(keystoreType, other.keystoreType)
                    && Objects.equals(keystorePassword, other.keystorePassword)
                    && Objects.equals(alias, other.alias)
                    && Objects.equals(aliasPassword, other.aliasPassword)
                    && Objects.equals(keystoreFile, other.keystoreFile);
        }
    }
}