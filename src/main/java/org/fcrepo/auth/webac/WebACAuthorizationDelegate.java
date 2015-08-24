package org.fcrepo.auth.webac;

import java.util.Set;

import javax.jcr.Session;

import org.fcrepo.auth.roles.common.AbstractRolesAuthorizationDelegate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class WebACAuthorizationDelegate extends AbstractRolesAuthorizationDelegate {

    /**
     * Class-level logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(WebACAuthorizationDelegate.class);
    
	@Override
	public boolean rolesHavePermission(Session userSession, String absPath,
			String[] actions, Set<String> roles) {
		boolean permit = false;
        LOGGER.debug("Request for actions: {}, on path: {}, with roles: {}. Permission={}",
                actions,
                absPath,
                roles,
                permit);
        
		return permit;
	}

}
