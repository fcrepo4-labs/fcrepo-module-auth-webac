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

import static org.fcrepo.auth.common.FedoraAuthorizationDelegate.FEDORA_USER_PRINCIPAL;
import static org.fcrepo.auth.webac.URIConstants.FOAF_AGENT_VALUE;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Mockito.when;

import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.jcr.Node;
import javax.jcr.RepositoryException;

import org.fcrepo.auth.roles.common.AccessRolesProvider;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.modeshape.jcr.ModeShapePermissions;
import org.modeshape.jcr.api.Session;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Unit test for the WebAC Authorization Delegate.
 *
 * @author Peter Eichman
 * @since Aug 24, 2015
 */
@RunWith(MockitoJUnitRunner.class)
public class WebACAuthorizationDelegateTest {

    private WebACAuthorizationDelegate webacAD;

    @Mock
    private Session mockSession;

    @Mock
    private Principal mockPrincipal;

    @Mock
    private Node mockNode;

    @Mock
    private AccessRolesProvider mockAccessRolesProvider;

    private static final String USER = "fakeUser";
    private static final String PATH = "/fake/path";

    @Before
    public void setUp() throws RepositoryException {
        when(mockSession.getAttribute(FEDORA_USER_PRINCIPAL)).thenReturn(mockPrincipal);
        when(mockSession.getNode(PATH)).thenReturn(mockNode);
        when(mockPrincipal.getName()).thenReturn(USER);
        webacAD = new WebACAuthorizationDelegate();
        ReflectionTestUtils.setField(webacAD, "accessRolesProvider", mockAccessRolesProvider);
    }

    @Test
    public void testAllowedWritePermissionForReadWriteUser() {
        final Map<String, List<String>> readWriteUserRoles = new HashMap<>();
        readWriteUserRoles.put(USER, new ArrayList<>(getReadWriteRoles()));
        when(mockAccessRolesProvider.getRoles(any(Node.class), anyBoolean())).thenReturn(readWriteUserRoles);
        assertTrue(webacAD.rolesHavePermission(mockSession, PATH, getWriteActions(), getWriteRoles()));
    }

    @Test
    public void testDisallowedWritePermissionForReadOnlyUser() {
        final Map<String, List<String>> readUserRoles = new HashMap<>();
        readUserRoles.put(USER, new ArrayList<>(getReadRoles()));
        when(mockAccessRolesProvider.getRoles(any(Node.class), anyBoolean())).thenReturn(readUserRoles);
        assertFalse(webacAD.rolesHavePermission(mockSession, PATH, getWriteActions(), getWriteRoles()));
    }

    @Test
    public void testAnonymousPrincipalIsFoafAgent() {
        assertTrue(FOAF_AGENT_VALUE.equals(webacAD.getEveryonePrincipal().getName()));
    }

    private static Set<String> getReadRoles() {
        final Set<String> readRoles = new HashSet<>();
        readRoles.add(URIConstants.WEBAC_MODE_READ_VALUE);
        return readRoles;
    }

    private static String[] getWriteActions() {
        final String[] writeActions =  new String[2];
        writeActions[0] = ModeShapePermissions.ADD_NODE;
        writeActions[1] = ModeShapePermissions.SET_PROPERTY;
        return writeActions;
    }

    private static Set<String> getWriteRoles() {
        final Set<String> readWriteRoles = new HashSet<>();
        readWriteRoles.add(URIConstants.WEBAC_MODE_WRITE_VALUE);
        return readWriteRoles;
    }

    private static Set<String> getReadWriteRoles() {
        final Set<String> readWriteRoles = new HashSet<>();
        readWriteRoles.add(URIConstants.WEBAC_MODE_READ_VALUE);
        readWriteRoles.add(URIConstants.WEBAC_MODE_WRITE_VALUE);
        return readWriteRoles;
    }

    private static String getFakeUser() {
        return USER;
    }
}
