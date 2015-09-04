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
package org.fcrepo.auth.webac.impl;

import static com.hp.hpl.jena.rdf.model.ModelFactory.createDefaultModel;
import static org.apache.jena.riot.Lang.TTL;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_ACCESS_CONTROL_VALUE;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_MODE_READ_VALUE;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_MODE_WRITE_VALUE;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_AUTHORIZATION;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.util.ReflectionTestUtils.setField;

import java.net.URI;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.jcr.Node;
import javax.jcr.RepositoryException;
import javax.jcr.Property;
import javax.jcr.Session;

import com.hp.hpl.jena.graph.Triple;
import com.hp.hpl.jena.rdf.model.Model;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFDataMgr;
import org.fcrepo.auth.roles.common.AccessRolesProvider;
import org.fcrepo.kernel.api.models.FedoraResource;
import org.fcrepo.kernel.api.services.NodeService;
import org.fcrepo.kernel.api.utils.iterators.RdfStream;
import org.fcrepo.kernel.modeshape.rdf.impl.PropertiesRdfContext;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

/**
 * @author acoburn
 * @since 9/3/15
 */
@RunWith(MockitoJUnitRunner.class)
public class WebACAccessRolesProviderTest {

    private AccessRolesProvider roleProvider;

    private final String ACL_PATH = "/acls";

    @Mock
    private Node mockNode;

    @Mock
    private Node mockParentNode;

    @Mock
    private Session mockSession;

    @Mock
    private NodeService mockNodeService;

    @Mock
    private FedoraResource mockResource;

    @Mock
    private FedoraResource mockParentResource;

    @Mock
    private FedoraResource mockAclResource;

    @Mock
    private FedoraResource mockAuthorizationResource1;

    @Mock
    private FedoraResource mockAuthorizationResource2;

    @Mock
    private Property mockProperty;

    @Before
    public void setUp() throws RepositoryException {

        roleProvider = new WebACAccessRolesProvider();
        setField(roleProvider, "nodeService", mockNodeService);

        when(mockNodeService.cast(mockNode)).thenReturn(mockResource);
        when(mockNode.getSession()).thenReturn(mockSession);

        when(mockResource.getNode()).thenReturn(mockNode);
        when(mockNode.getDepth()).thenReturn(0);
        when(mockResource.hasProperty(WEBAC_ACCESS_CONTROL_VALUE)).thenReturn(true);
        when(mockResource.getProperty(WEBAC_ACCESS_CONTROL_VALUE)).thenReturn(mockProperty);
    }

    @Test
    public void noAclTest() throws RepositoryException {
        final String accessTo = "http://localhost:8080/rest/dark/archive/sunshine";

        when(mockResource.getPath()).thenReturn(accessTo);
        when(mockResource.hasProperty(WEBAC_ACCESS_CONTROL_VALUE)).thenReturn(false);
        when(mockResource.getContainer()).thenReturn(mockParentResource);
        when(mockParentResource.hasProperty(WEBAC_ACCESS_CONTROL_VALUE)).thenReturn(false);
        when(mockParentResource.getNode()).thenReturn(mockParentNode);
        when(mockNode.getDepth()).thenReturn(1);
        when(mockParentNode.getDepth()).thenReturn(0);

        final Map<String, List<String>> roles = roleProvider.getRoles(mockNode, true);

        assertTrue("There should be no agents in the roles map", roles.isEmpty());
    }

    @Test
    public void acl01ParentTest() throws RepositoryException {
        final String agent = "smith123";
        final String accessTo = "http://localhost:8080/rest/webacl_box1";
        final String acl = "/acls/01";
        final String auth = acl + "/authorization.ttl";

        when(mockResource.getPath()).thenReturn(accessTo);
        when(mockResource.hasProperty(WEBAC_ACCESS_CONTROL_VALUE)).thenReturn(false);
        when(mockResource.getContainer()).thenReturn(mockParentResource);
        when(mockResource.getPath()).thenReturn(accessTo + "/foo");
        when(mockNode.getDepth()).thenReturn(1);

        when(mockParentResource.hasProperty(WEBAC_ACCESS_CONTROL_VALUE)).thenReturn(true);
        when(mockParentResource.getNode()).thenReturn(mockParentNode);
        when(mockParentResource.getProperty(WEBAC_ACCESS_CONTROL_VALUE)).thenReturn(mockProperty);
        when(mockParentResource.getPath()).thenReturn(accessTo);
        when(mockParentNode.getDepth()).thenReturn(0);

        when(mockProperty.getString()).thenReturn(acl);
        when(mockNodeService.find(mockSession, acl)).thenReturn(mockAclResource);
        when(mockAclResource.getPath()).thenReturn(acl);

        when(mockAuthorizationResource1.getTypes()).thenReturn(Arrays.asList(WEBAC_AUTHORIZATION));
        when(mockAuthorizationResource1.getPath()).thenReturn(auth);
        when(mockAuthorizationResource1.getTriples(anyObject(),
                    eq(PropertiesRdfContext.class))).thenReturn(getRdfStreamFromResource(auth, TTL));

        when(mockAclResource.getChildren()).thenReturn(Arrays.asList(mockAuthorizationResource1).iterator());

        final Map<String, List<String>> roles = roleProvider.getRoles(mockNode, true);

        assertEquals("There should be exactly one agent in the role map", 1, roles.size());
        assertEquals("The agent should have exactly two modes", 2, roles.get(agent).size());
        assertTrue("The agent should be able to read", roles.get(agent).contains(WEBAC_MODE_READ_VALUE));
        assertTrue("The agent should be able to write", roles.get(agent).contains(WEBAC_MODE_WRITE_VALUE));
    }

    @Test
    public void acl01Test1() throws RepositoryException {
        final String agent = "smith123";
        final String accessTo = "http://localhost:8080/rest/webacl_box1";
        final String acl = "/acls/01";
        final String auth = acl + "/authorization.ttl";

        when(mockNodeService.find(mockSession, acl)).thenReturn(mockAclResource);
        when(mockProperty.getString()).thenReturn(acl);
        when(mockAclResource.getPath()).thenReturn(acl);
        when(mockResource.getPath()).thenReturn(accessTo);
        when(mockAuthorizationResource1.getTypes()).thenReturn(Arrays.asList(WEBAC_AUTHORIZATION));
        when(mockAuthorizationResource1.getPath()).thenReturn(auth);
        when(mockAuthorizationResource1.getTriples(anyObject(),
                    eq(PropertiesRdfContext.class))).thenReturn(getRdfStreamFromResource(auth, TTL));

        when(mockAclResource.getChildren()).thenReturn(Arrays.asList(mockAuthorizationResource1).iterator());

        final Map<String, List<String>> roles = roleProvider.getRoles(mockNode, true);

        assertEquals("There should be exactly one agent in the role map", 1, roles.size());
        assertEquals("The agent should have exactly two modes", 2, roles.get(agent).size());
        assertTrue("The agent should be able to read", roles.get(agent).contains(WEBAC_MODE_READ_VALUE));
        assertTrue("The agent should be able to write", roles.get(agent).contains(WEBAC_MODE_WRITE_VALUE));
    }

    @Test
    public void acl01Test2() throws RepositoryException {
        final String accessTo = "http://localhost:8080/rest/webacl_box2";
        final String acl = "/acls/01";
        final String auth = acl + "/authorization.ttl";

        when(mockNodeService.find(mockSession, acl)).thenReturn(mockAclResource);
        when(mockProperty.getString()).thenReturn(acl);
        when(mockAclResource.getPath()).thenReturn(acl);
        when(mockResource.getPath()).thenReturn(accessTo);

        when(mockAuthorizationResource1.getTypes()).thenReturn(Arrays.asList(WEBAC_AUTHORIZATION));
        when(mockAuthorizationResource1.getPath()).thenReturn(auth);
        when(mockAuthorizationResource1.getTriples(anyObject(),
                    eq(PropertiesRdfContext.class))).thenReturn(getRdfStreamFromResource(auth, TTL));

        when(mockAclResource.getChildren()).thenReturn(Arrays.asList(mockAuthorizationResource1).iterator());

        final Map<String, List<String>> roles = roleProvider.getRoles(mockNode, true);

        assertTrue("There should be no agents associated with this object", roles.isEmpty());
    }

    @Test
    public void acl02Test() throws RepositoryException {
        final String agent = "Editors";
        final String accessTo = "http://localhost:8080/rest/box/bag/collection";
        final String acl = "/acls/02";
        final String auth = acl + "/authorization.ttl";

        when(mockNodeService.find(mockSession, acl)).thenReturn(mockAclResource);
        when(mockProperty.getString()).thenReturn(acl);
        when(mockAclResource.getPath()).thenReturn(acl);
        when(mockResource.getPath()).thenReturn(accessTo);

        when(mockAuthorizationResource1.getTypes()).thenReturn(Arrays.asList(WEBAC_AUTHORIZATION));
        when(mockAuthorizationResource1.getPath()).thenReturn(auth);
        when(mockAuthorizationResource1.getTriples(anyObject(),
                    eq(PropertiesRdfContext.class))).thenReturn(getRdfStreamFromResource(auth, TTL));

        when(mockAclResource.getChildren()).thenReturn(Arrays.asList(mockAuthorizationResource1).iterator());

        final Map<String, List<String>> roles = roleProvider.getRoles(mockNode, true);

        assertEquals("There should be exactly one agent in the role map", 1, roles.size());
        assertEquals("The agent should have exactly two modes", 2, roles.get(agent).size());
        assertTrue("The agent should be able to read", roles.get(agent).contains(WEBAC_MODE_READ_VALUE));
        assertTrue("The agent should be able to write", roles.get(agent).contains(WEBAC_MODE_WRITE_VALUE));
    }

    @Test
    public void acl03Test1() throws RepositoryException {
        final String agent = "http://xmlns.com/foaf/0.1/Agent";
        final String accessTo = "http://localhost:8080/rest/dark/archive/sunshine";
        final String acl = "/acls/03";
        final String auth1 = acl + "/auth_restricted.ttl";
        final String auth2 = acl + "/auth_open.ttl";

        when(mockNodeService.find(mockSession, acl)).thenReturn(mockAclResource);
        when(mockProperty.getString()).thenReturn(acl);
        when(mockAclResource.getPath()).thenReturn(acl);
        when(mockResource.getPath()).thenReturn(accessTo);

        when(mockAuthorizationResource1.getTypes()).thenReturn(Arrays.asList(WEBAC_AUTHORIZATION));
        when(mockAuthorizationResource1.getPath()).thenReturn(auth1);
        when(mockAuthorizationResource1.getTriples(anyObject(),
                    eq(PropertiesRdfContext.class))).thenReturn(getRdfStreamFromResource(auth1, TTL));

        when(mockAuthorizationResource2.getTypes()).thenReturn(Arrays.asList(WEBAC_AUTHORIZATION));
        when(mockAuthorizationResource2.getPath()).thenReturn(auth2);
        when(mockAuthorizationResource2.getTriples(anyObject(),
                    eq(PropertiesRdfContext.class))).thenReturn(getRdfStreamFromResource(auth2, TTL));

        when(mockAclResource.getChildren()).thenReturn(
                Arrays.asList(mockAuthorizationResource1, mockAuthorizationResource2).iterator());

        final Map<String, List<String>> roles = roleProvider.getRoles(mockNode, true);

        assertEquals("There should be exactly one agent in the roles map", 1, roles.size());
        assertEquals("The agent should have exactly one mode", 1, roles.get(agent).size());
        assertTrue("The agent should be able to read", roles.get(agent).contains(WEBAC_MODE_READ_VALUE));
    }

    @Test
    public void acl03Test2() throws RepositoryException {
        final String agent = "Restricted";
        final String accessTo = "http://localhost:8080/rest/dark/archive";
        final String acl = "/acls/03";
        final String auth1 = acl + "/auth_restricted.ttl";
        final String auth2 = acl + "/auth_open.ttl";

        when(mockNodeService.find(mockSession, acl)).thenReturn(mockAclResource);
        when(mockProperty.getString()).thenReturn(acl);
        when(mockAclResource.getPath()).thenReturn(acl);
        when(mockResource.getPath()).thenReturn(accessTo);

        when(mockAuthorizationResource1.getTypes()).thenReturn(Arrays.asList(WEBAC_AUTHORIZATION));
        when(mockAuthorizationResource1.getPath()).thenReturn(auth1);
        when(mockAuthorizationResource1.getTriples(anyObject(),
                    eq(PropertiesRdfContext.class))).thenReturn(getRdfStreamFromResource(auth1, TTL));

        when(mockAuthorizationResource2.getTypes()).thenReturn(Arrays.asList(WEBAC_AUTHORIZATION));
        when(mockAuthorizationResource2.getPath()).thenReturn(auth2);
        when(mockAuthorizationResource2.getTriples(anyObject(),
                    eq(PropertiesRdfContext.class))).thenReturn(getRdfStreamFromResource(auth2, TTL));

        when(mockAclResource.getChildren()).thenReturn(
                Arrays.asList(mockAuthorizationResource1, mockAuthorizationResource2).iterator());

        final Map<String, List<String>> roles = roleProvider.getRoles(mockNode, true);

        assertEquals("There should be exactly one agent", 1, roles.size());
        assertEquals("The agent should have one mode", 1, roles.get(agent).size());
        assertTrue("The agent should be able to read", roles.get(agent).contains(WEBAC_MODE_READ_VALUE));
    }

    @Test
    public void acl04Test() throws RepositoryException {
        final String agent1 = "http://xmlns.com/foaf/0.1/Agent";
        final String agent2 = "Editors";
        final String accessTo = "http://localhost:8080/rest/public_collection";
        final String acl = "/acls/04";
        final String auth1 = acl + "/auth1.ttl";
        final String auth2 = acl + "/auth2.ttl";

        when(mockNodeService.find(mockSession, acl)).thenReturn(mockAclResource);
        when(mockProperty.getString()).thenReturn(acl);
        when(mockAclResource.getPath()).thenReturn(acl);
        when(mockResource.getPath()).thenReturn(accessTo);

        when(mockAuthorizationResource1.getTypes()).thenReturn(Arrays.asList(WEBAC_AUTHORIZATION));
        when(mockAuthorizationResource1.getPath()).thenReturn(auth1);
        when(mockAuthorizationResource1.getTriples(anyObject(),
                    eq(PropertiesRdfContext.class))).thenReturn(getRdfStreamFromResource(auth1, TTL));

        when(mockAuthorizationResource2.getTypes()).thenReturn(Arrays.asList(WEBAC_AUTHORIZATION));
        when(mockAuthorizationResource2.getPath()).thenReturn(auth2);
        when(mockAuthorizationResource2.getTriples(anyObject(),
                    eq(PropertiesRdfContext.class))).thenReturn(getRdfStreamFromResource(auth2, TTL));

        when(mockAclResource.getChildren()).thenReturn(
                Arrays.asList(mockAuthorizationResource1, mockAuthorizationResource2).iterator());

        final Map<String, List<String>> roles = roleProvider.getRoles(mockNode, true);

        assertEquals("There should be exactly two agents", 2, roles.size());
        assertEquals("The agent should have one mode", 1, roles.get(agent1).size());
        assertTrue("The agent should be able to read", roles.get(agent1).contains(WEBAC_MODE_READ_VALUE));
        assertEquals("The agent should have two modes", 2, roles.get(agent2).size());
        assertTrue("The agent should be able to read", roles.get(agent2).contains(WEBAC_MODE_READ_VALUE));
        assertTrue("The agent should be able to write", roles.get(agent2).contains(WEBAC_MODE_READ_VALUE));
    }

    @Test
    public void acl05Test() throws RepositoryException {
        final String agent1 = "http://xmlns.com/foaf/0.1/Agent";
        final String agent2 = "Admins";
        final String accessTo = "http://localhost:8080/rest/mixedCollection";
        final String acl = "/acls/05";
        final String auth1 = acl + "/auth_restricted.ttl";
        final String auth2 = acl + "/auth_open.ttl";

        when(mockNodeService.find(mockSession, acl)).thenReturn(mockAclResource);
        when(mockProperty.getString()).thenReturn(acl);
        when(mockAclResource.getPath()).thenReturn(acl);
        when(mockResource.getPath()).thenReturn(accessTo);
        when(mockResource.getTypes()).thenReturn(Arrays.asList(URI.create("http://example.com/terms#publicImage")));

        when(mockAuthorizationResource1.getTypes()).thenReturn(Arrays.asList(WEBAC_AUTHORIZATION));
        when(mockAuthorizationResource1.getPath()).thenReturn(auth1);
        when(mockAuthorizationResource1.getTriples(anyObject(),
                    eq(PropertiesRdfContext.class))).thenReturn(getRdfStreamFromResource(auth1, TTL));

        when(mockAuthorizationResource2.getTypes()).thenReturn(Arrays.asList(WEBAC_AUTHORIZATION));
        when(mockAuthorizationResource2.getPath()).thenReturn(auth2);
        when(mockAuthorizationResource2.getTriples(anyObject(),
                    eq(PropertiesRdfContext.class))).thenReturn(getRdfStreamFromResource(auth2, TTL));

        when(mockAclResource.getChildren()).thenReturn(
                Arrays.asList(mockAuthorizationResource1, mockAuthorizationResource2).iterator());

        final Map<String, List<String>> roles = roleProvider.getRoles(mockNode, true);

        assertEquals("There should be exactly two agents", 2, roles.size());
        assertEquals("The agent should have one mode", 1, roles.get(agent1).size());
        assertTrue("The agent should be able to read", roles.get(agent1).contains(WEBAC_MODE_READ_VALUE));
        assertEquals("The agent should have one mode", 1, roles.get(agent2).size());
        assertTrue("The agent should be able to read", roles.get(agent2).contains(WEBAC_MODE_READ_VALUE));
    }

    @Test
    public void acl05Test2() throws RepositoryException {
        final String agent1 = "http://xmlns.com/foaf/0.1/Agent";
        final String accessTo = "http://localhost:8080/rest/someOtherCollection";
        final String acl = "/acls/05";
        final String auth1 = acl + "/auth_restricted.ttl";
        final String auth2 = acl + "/auth_open.ttl";

        when(mockNodeService.find(mockSession, acl)).thenReturn(mockAclResource);
        when(mockProperty.getString()).thenReturn(acl);
        when(mockAclResource.getPath()).thenReturn(acl);
        when(mockResource.getPath()).thenReturn(accessTo);
        when(mockResource.getTypes()).thenReturn(Arrays.asList(URI.create("http://example.com/terms#publicImage")));

        when(mockAuthorizationResource1.getTypes()).thenReturn(Arrays.asList(WEBAC_AUTHORIZATION));
        when(mockAuthorizationResource1.getPath()).thenReturn(auth1);
        when(mockAuthorizationResource1.getTriples(anyObject(),
                    eq(PropertiesRdfContext.class))).thenReturn(getRdfStreamFromResource(auth1, TTL));

        when(mockAuthorizationResource2.getTypes()).thenReturn(Arrays.asList(WEBAC_AUTHORIZATION));
        when(mockAuthorizationResource2.getPath()).thenReturn(auth2);
        when(mockAuthorizationResource2.getTriples(anyObject(),
                    eq(PropertiesRdfContext.class))).thenReturn(getRdfStreamFromResource(auth2, TTL));

        when(mockAclResource.getChildren()).thenReturn(
                Arrays.asList(mockAuthorizationResource1, mockAuthorizationResource2).iterator());

        final Map<String, List<String>> roles = roleProvider.getRoles(mockNode, true);

        assertEquals("There should be exactly agent", 1, roles.size());
        assertEquals("The agent should have one mode", 1, roles.get(agent1).size());
        assertTrue("The agent should be able to read", roles.get(agent1).contains(WEBAC_MODE_READ_VALUE));
    }


    private static RdfStream getRdfStreamFromResource(final String resourcePath, final Lang lang) {
        final Model model = createDefaultModel();

        RDFDataMgr.read(model, WebACAccessRolesProviderTest.class.getResourceAsStream(resourcePath), lang);

        final List<Triple> triples = new ArrayList<>();
        model.listStatements().forEachRemaining(x -> {
            triples.add(x.asTriple());
        });

        return new RdfStream(triples);
    }
}
