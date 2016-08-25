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
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;


public class KerberosAuthenticator {
    private static final Log log = LogFactory.getLog(KerberosAuthenticator.class);
    private String serverPrincipal;
    private String realm;
    private File keyTabFile;
    private boolean isEstablished;
    private GSSCredential kerberosCredentials;
    private GSSManager gssManager = GSSManager.getInstance();

    /**
     * Authenticator initialize with the given kerberos parameters.
     * @param serverPrincipal  a service or user that is known to the Kerberos system.
     * @param realm a  domain name that is registered in Kerboros system.
     * @param keyTabFilePath a path for generated keytab file where kerberos credentials encrypted.
     */
    public KerberosAuthenticator(String serverPrincipal, String realm, String keyTabFilePath) {
        this.serverPrincipal = serverPrincipal;
        this.realm = realm;
        this.keyTabFile = new File(keyTabFilePath);
        try {
            kerberosCredentials = createCredentials();
        } catch (PrivilegedActionException | LoginException | GSSException e) {
            //TODO: what if the exception occurred
            log.error(e.getMessage());
        }
    }

    private Configuration getJaasKrb5TicketCfg() {
        return new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                Map<String, String> options = new HashMap<String, String>();
                options.put("principal", serverPrincipal);
                options.put("realm", realm);
                options.put("keyTab", keyTabFile.getAbsolutePath());
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

    private GSSCredential createCredentials()
            throws PrivilegedActionException, LoginException, GSSException {
        Principal principal = new KerberosPrincipal(serverPrincipal, KerberosPrincipal.KRB_NT_SRV_INST);
        Set<Principal> principals = new HashSet<Principal>();
        principals.add(principal);
        Subject subject = new Subject(false, principals, new HashSet<Object>(),
                new HashSet<Object>());
        LoginContext loginContext = new LoginContext("Server", subject, null, getJaasKrb5TicketCfg());
        try {
            loginContext.login();
        } catch (LoginException e) {
            //TODO: what if the exception occurred
            log.error(e.getMessage());
        }

        final Oid mechOid = new Oid("1.3.6.1.5.5.2");
        final PrivilegedExceptionAction<GSSCredential> action =
                new PrivilegedExceptionAction<GSSCredential>() {
                    public GSSCredential run() throws GSSException {
                        return gssManager.createCredential(null, GSSCredential.INDEFINITE_LIFETIME,
                                mechOid, GSSCredential.ACCEPT_ONLY);
                    }
                };

        return Subject.doAs(loginContext.getSubject(), action);
    }

    /**
     * Accept a client token to establish a secure communication channel with AD.
     * @param gssToken the client side token (client side, as in the token had
     *        to be bootstrapped by the client and this peer uses that token
     *        to update the GSSContext)
     * @return server tokens that the server sends over to the peer.
     * @throws GSSException
     */
    public byte[] processToken(byte[] gssToken) throws GSSException {
        GSSContext context = gssManager.createContext(kerberosCredentials);
        byte[] serverToken = context.acceptSecContext(gssToken, 0, gssToken.length);
        if (context.isEstablished()) {
            setContextEstablished(true);
        } else {
            setContextEstablished(false);
        }
        return serverToken;
    }

    /**
     * State of the communication channel with the user token.
     * @return a boolean to indicate whether the token was used to successfully
     *         establish a communication channel.
     */
    public boolean isEstablished() {
        return isEstablished;
    }

    private void setContextEstablished(boolean established) {
        isEstablished = established;
    }
}
