/*
 *
 *   Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.rest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.Oid;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.HashSet;


public class KerberosAuthenticator {
    private static final Log log = LogFactory.getLog(KerberosAuthenticator.class);
    private String serverPrincipal;
    private String realm;
    private String keytab;

    private GSSCredential localKerberosCredentials;
    private GSSManager gssManager = GSSManager.getInstance();

    private static KerberosAuthenticator instance;

    private KerberosAuthenticator() {
        this.init();
    }

    public void init() {
        try {
            setConfigFilePaths();
            setKerberosCredentials(createCredentials());
        } catch (PrivilegedActionException | LoginException | GSSException e) {
            //TODO: what if the exception occurred
            log.error(e.getMessage());
        }
    }

    public static KerberosAuthenticator getInstance() {
        if (instance == null) {
            synchronized (KerberosAuthenticator.class) {
                if (instance == null) {
                    instance = new KerberosAuthenticator();
                }
            }
        }
        return instance;
    }

    /**
     * Set jaas.conf and krb5 paths
     */
    private void setConfigFilePaths() {
        Properties props = new Properties();
        try {
            props.load(new FileInputStream("." + File.separator + "repository" + File.separator + "conf" +
                    File.separator + "server.properties"));
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.setProperty("sun.security.krb5.debug", "true");
        System.setProperty("java.security.auth.login.config", "." + File.separator + "repository" + File.separator + "conf" +
                File.separator + "jaas.conf");
        serverPrincipal = props.getProperty("principal");
        realm = props.getProperty("realm");
        keytab = props.getProperty("keyTab");
    }

    private Configuration getJaasKrb5TicketCfg(
            final String principal, final String realm, final File keytab) {
        return new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                Map<String, String> options = new HashMap<String, String>();
                options.put("principal", principal);
                options.put("realm", realm);
                options.put("keyTab", keytab.getAbsolutePath());
                options.put("doNotPrompt", "true");
                options.put("useKeyTab", "true");
                options.put("storeKey", "true");
                options.put("isInitiator", "false");

                return new AppConfigurationEntry[]{
                        new AppConfigurationEntry(
                                "com.sun.security.auth.module.Krb5LoginModule",
                                LoginModuleControlFlag.REQUIRED, options)
                };
            }
        };
    }

    private GSSCredential createServerCredentials()
            throws PrivilegedActionException, LoginException, GSSException {
        Principal principal = new KerberosPrincipal(serverPrincipal, KerberosPrincipal.KRB_NT_SRV_INST);
        Set<Principal> principals = new HashSet<Principal>();
        principals.add(principal);
        Subject subject = new Subject(false, principals, new HashSet<Object>(),
                new HashSet<Object>());
        LoginContext loginContext = new LoginContext("Server", subject, null, getJaasKrb5TicketCfg(serverPrincipal,
                realm, new File(keytab)));
        try {
            loginContext.login();
        } catch (LoginException e) {
            //TODO : Handle this properly
            log.error(e.getMessage());
        }

        return createCredentialsForSubject(loginContext.getSubject());
    }


    private GSSCredential createCredentialsForSubject(final Subject subject) throws PrivilegedActionException,
            GSSException {
        final Oid mechOid = new Oid("1.3.6.1.5.5.2");
        final PrivilegedExceptionAction<GSSCredential> action =
                new PrivilegedExceptionAction<GSSCredential>() {
                    public GSSCredential run() throws GSSException {
                        return gssManager.createCredential(null, GSSCredential.INDEFINITE_LIFETIME,
                                mechOid, GSSCredential.ACCEPT_ONLY);
                    }
                };

        return Subject.doAs(subject, action);
    }

    private GSSCredential createCredentials()
            throws PrivilegedActionException, LoginException, GSSException {
        GSSCredential gssCredential = createServerCredentials();
        return gssCredential;
    }

    private void setKerberosCredentials(GSSCredential gssCredential) {
        localKerberosCredentials = gssCredential;
    }

    public byte[] processToken(byte[] gssToken) throws GSSException {
        GSSContext context = gssManager.createContext(localKerberosCredentials);
        byte[] serverToken = context.acceptSecContext(gssToken, 0, gssToken.length);
        if (context.isEstablished()) {
            return serverToken;
        }
        return new byte[0];
    }
}
