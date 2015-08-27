package org.fcrepo.auth.webac.impl;

import java.util.Set;

import org.fcrepo.auth.webac.AuthorizationHandler;

import com.hp.hpl.jena.vocabulary.RDF;

/**
 * @author mohideen
 * @date 8/27/15.
 */
public class AuthorizationHandlerImpl implements AuthorizationHandler {

    public Set<WebACAuthorization> getAuthorizations(String aclPath, String resourcePath, Set<RDF> objectTypes, String agent) {
        return null;
    }

    public Set<WebACAuthorization> getAuthorizations(FedoraResource resource, String agent) {
        return null;
    }
}
