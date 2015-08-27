/**
 * Copyright 2015 DuraSpace, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.fcrepo.auth.webac;

import static org.fcrepo.auth.webac.URIConstants.FOAF_AGENT_VALUE;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_HAS_ACL;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_MODE_APPEND;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_MODE_READ;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_MODE_WRITE;

import java.net.URI;
import java.security.Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import javax.jcr.Session;

import org.fcrepo.auth.common.FedoraUserSecurityContext;
import org.fcrepo.auth.roles.common.AbstractRolesAuthorizationDelegate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Authorization Delegate responsible for resolving Fedora's permissions using Web Access Control (WebAC) access
 * control lists.
 *
 * @author Peter Eichman
 * @author acoburn
 * @since Aug 24, 2015
 */
public class WebACAuthorizationDelegate extends AbstractRolesAuthorizationDelegate {

    /**
     * Class-level logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(WebACAuthorizationDelegate.class);

    /**
     * The security principal for every request, that represents the foaf:Agent agent class that is used to designate
     * "everyone".
     */
    private static final Principal EVERYONE = new Principal() {

        @Override
        public String getName() {
            return FOAF_AGENT_VALUE;
        }

        @Override
        public String toString() {
            return getName();
        }

    };

    private static final Map<String, URI> actionMap;

    static {
        Map<String, URI> map = new HashMap<>();
        map.put("GET", WEBAC_MODE_READ);
        map.put("POST", WEBAC_MODE_APPEND);
        map.put("PUT", WEBAC_MODE_WRITE);
        map.put("DELETE", WEBAC_MODE_WRITE);
        map.put("PATCH", WEBAC_MODE_WRITE);
        map.put("OPTIONS", WEBAC_MODE_READ);
        actionMap = Collections.unmodifiableMap(map);
    }

    @Override
    public boolean rolesHavePermission(final Session userSession, final String absPath,
            final String[] actions, final Set<String> roles) {

        // This is not correct -- we should get it from the container or header, etc
        final String agent = userSession.getUserID();

        final List<URI> actionURIs = actionsAsURIs(actions);

        final Optional<URI> effectiveACL = getEffectiveAcl(new FedoraResourceImpl(userSession.getNode(absPath)));

        final AuthorizationHandler authHandler = new AuthorizationHandlerImpl();

        // The getAuthorizations(URI, String, String) signature doesn't exist
        final Optional<boolean> userPermission = effectiveACL
                    .map(x -> authHandler.getAuthorizations(x, absPath, agent))
                    .map(x -> isPermitted(actionURIs, x));

        // The getAuthorizations(URI, String, Set<String>) signature doesn't exist
        final Optional<boolean> groupPermission = effectiveACL
                    .map(x -> authHandler.getAuthorizations(x, absPath, roles))
                    .map(x -> isPermitted(actionURIs, x));

        final boolean permit = userPermission
                                .orElse(groupPermission.orElse(false));

        LOGGER.debug("Request for actions: {}, on path: {}, with roles: {}. Permission={}",
                actions,
                absPath,
                roles,
                permit);

        return permit;
    }

    @Override
    public Principal getEveryonePrincipal() {
        return EVERYONE;
    }

    @Override
    public FedoraUserSecurityContext getFedoraUserSecurityContext(final Principal userPrincipal) {
        return new FedoraWebACUserSecurityContext(userPrincipal, this);
    }

    /**
     * Given a set of WebACAuthorization objects, determine if the given modes are allowed.
     *
     * NOTE: Its use above should be replaced with a curried version of this function.
     */
    private boolean isPermitted(final Set<URI> modes, final Set<WebACAuthorization> acl) {
        return acl.stream()
                  .map(WebACAuthorization::getModes)
                  .flatMap(Collection::stream)
                  .distinct()
                  .collect(Collectors.toList())
                  .containsAll(modes);
    }

    /**
     * A convenience method for converting an array of actions to a List<URI> structure.
     */
    private List<URI> actionsAsUris(final String[] actions) {
        final List<URI> uris = new ArrayList<>();
        for (final String a : actions) {
            uris.add(actionsMap.get(a));
        }
        return uris;
    }

    /**
     * Find the effective ACL as a URI. It may or may not exist, and it may or may
     * not be a fedora resource.
     */
    private Optional<URI> getEffectiveAcl(final FedoraResource resource) {
        if (resource.hasProperty(WEBAC_HAS_ACL)) {
            return Optional<URI>.of(new URI(resource.getProperty(WEBAC_HAS_ACL).getString()));
        } else if (resource.getNode().getDepth() == 0) {
            return Optional<URI>.empty();
        } else {
            return getEffectiveAcl(resource.getContainer());
        }
    }
}
