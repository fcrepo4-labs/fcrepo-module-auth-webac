package org.fcrepo.auth.webac;

import java.util.Set;

import javax.jcr.Session;

import org.fcrepo.auth.roles.common.AbstractRolesAuthorizationDelegate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Authorization Delegate responsible for resolving Fedora's permissions using Web Access Control (WebAC) access
 * control lists.
 *
 * @author Peter Eichman
 * @date Aug 24, 2015
 */
public class WebACAuthorizationDelegate extends AbstractRolesAuthorizationDelegate {

    /**
     * Class-level logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(WebACAuthorizationDelegate.class);

    @Override
    public boolean rolesHavePermission(final Session userSession, final String absPath,
            final String[] actions, final Set<String> roles) {
        final boolean permit = false;
        LOGGER.debug("Request for actions: {}, on path: {}, with roles: {}. Permission={}",
                actions,
                absPath,
                roles,
                permit);

        return permit;
    }

}
