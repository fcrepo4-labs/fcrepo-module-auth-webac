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
import static org.fcrepo.auth.webac.URIConstants.WEBAC_MODE_APPEND;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_MODE_READ;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_MODE_WRITE;
import static org.slf4j.LoggerFactory.getLogger;
import static java.util.Collections.unmodifiableMap;

import java.net.URI;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;
import javax.jcr.Session;

import org.fcrepo.auth.common.FedoraUserSecurityContext;
import org.fcrepo.auth.roles.common.AbstractRolesAuthorizationDelegate;
import org.fcrepo.auth.roles.common.AccessRolesProvider;
import org.fcrepo.kernel.api.services.NodeService;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;

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
    private static final Logger LOGGER = getLogger(WebACAuthorizationDelegate.class);

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

    @Inject
    private NodeService nodeService;

    @Autowired
    private AccessRolesProvider accessRolesProvider;

    private static final Map<String, URI> actionsMap;

    static {
        final Map<String, URI> map = new HashMap<>();
        map.put("GET", WEBAC_MODE_READ);
        map.put("POST", WEBAC_MODE_APPEND);
        map.put("PUT", WEBAC_MODE_WRITE);
        map.put("DELETE", WEBAC_MODE_WRITE);
        map.put("PATCH", WEBAC_MODE_WRITE);
        map.put("OPTIONS", WEBAC_MODE_READ);
        actionsMap = unmodifiableMap(map);
    }

    @Override
    public boolean rolesHavePermission(final Session userSession, final String absPath,
            final String[] actions, final Set<String> roles) {

        // use the user principal as the WebAC agent
        // if there is no logged-in user, the user principal will be the EVERYONE principal, so
        // the agent will be FOAF_AGENT_VALUE (i.e., the URI string for foaf:Agent)
        final Principal userPrincipal = (Principal) userSession.getAttribute(FEDORA_USER_PRINCIPAL);
        final String agent = userPrincipal.getName();

        try {
            final Map<String, List<String>> resourceAccessRoles =
                accessRolesProvider.getRoles(userSession.getNode(absPath), true);

            final Set<String> effectiveRoles = new HashSet<>();

            if (resourceAccessRoles.containsKey(agent)) {
                effectiveRoles.addAll(resourceAccessRoles.get(agent));
            } else {
                for (final String r : roles) {
                    if (resourceAccessRoles.containsKey(r)) {
                        effectiveRoles.addAll(resourceAccessRoles.get(r));
                    }
                }
            }

            final boolean permit = effectiveRoles.containsAll(actionsAsURIs(actions));

            LOGGER.debug("Request for actions: {}, on path: {}, with roles: {}. Permission={}",
                    actions,
                    absPath,
                    roles,
                    permit);

            return permit;
        } catch (final Exception ex) {
            return false;
        }
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
     * A convenience method for converting an array of actions to a List<URI> structure.
     */
    private static List<URI> actionsAsURIs(final String[] actions) {
        final List<URI> uris = new ArrayList<>();
        for (final String a : actions) {
            uris.add(actionsMap.get(a));
        }
        return uris;
    }
}
