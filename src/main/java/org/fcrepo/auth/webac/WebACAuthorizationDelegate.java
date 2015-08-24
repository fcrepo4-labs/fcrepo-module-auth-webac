package org.fcrepo.auth.webac;

import java.util.Set;

import javax.jcr.Session;

import org.fcrepo.auth.roles.common.AbstractRolesAuthorizationDelegate;

public class WebACAuthorizationDelegate extends AbstractRolesAuthorizationDelegate {

	@Override
	public boolean rolesHavePermission(Session userSession, String absPath,
			String[] actions, Set<String> roles) {
		return false;
	}

}
