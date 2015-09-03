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
import static org.fcrepo.kernel.api.utils.UncheckedFunction.uncheck;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_NAMESPACE_VALUE;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_AUTHORIZATION;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_ACCESSTO_VALUE;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_MODE_VALUE;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_ACCESSTO_CLASS_VALUE;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_AGENT_CLASS_VALUE;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_AGENT_VALUE;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_ACCESS_CONTROL_VALUE;

import java.net.URI;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;


import javax.jcr.Node;
import javax.jcr.RepositoryException;
import javax.jcr.Session;

import com.hp.hpl.jena.rdf.model.Model;
import com.hp.hpl.jena.rdf.model.Property;
import com.hp.hpl.jena.rdf.model.Resource;
import org.fcrepo.auth.roles.common.AccessRolesProvider;
import org.fcrepo.auth.webac.WebACAuthorization;
import org.fcrepo.kernel.api.exception.RepositoryRuntimeException;
import org.fcrepo.kernel.api.identifiers.IdentifierConverter;
import org.fcrepo.kernel.api.models.FedoraResource;
import org.fcrepo.kernel.modeshape.FedoraResourceImpl;
import org.fcrepo.kernel.modeshape.rdf.impl.DefaultIdentifierTranslator;
import org.fcrepo.kernel.modeshape.rdf.impl.PropertiesRdfContext;
import org.modeshape.jcr.value.Path;

/**
 * @author acoburn
 * @since 9/3/15
 */
class WebACAccessRolesProvider implements AccessRolesProvider {

    @Override
    public Map<String, List<String>> getRoles(final Node node, final boolean effective) {
        final FedoraResource resource = new FedoraResourceImpl(node);
        final List<URI> rdfTypes = resource.getTypes();
        final Optional<URI> effectiveAcl = getEffectiveAcl(resource);
        final List<String> resourcePaths = new ArrayList<>();
        try {
            resourcePaths.add(node.getPath());
        } catch (final RepositoryException ex) {
            throw new RepositoryRuntimeException(ex);
        }
        effectiveAcl.map(URI::toString).ifPresent(resourcePaths::add);

        final Predicate<WebACAuthorization> checkAccessTo = accessTo.apply(resourcePaths);
        final Predicate<WebACAuthorization> checkAccessToClass =
            accessToClass.apply(resource.getTypes().stream().map(URI::toString).collect(Collectors.toList()));

        final List<WebACAuthorization> authorizations = effectiveAcl
                .map(uncheck(x -> node.getSession().getNode(x.toString())))
                .map(uncheck(x -> getAuthorizations(x, node.getPath())))
                .orElse(new ArrayList<>());

        final Map<String, Set<String>> effectiveRoles = new HashMap<>();
        authorizations.stream()
            .filter(x -> checkAccessTo.test(x) || checkAccessToClass.test(x))
            .forEach(x -> {
                x.getAgents().stream()
                    .forEach(y -> {
                        effectiveRoles.putIfAbsent(y, new HashSet<>());
                        effectiveRoles.get(y).addAll(
                            x.getModes().stream()
                                        .map(URI::toString)
                                        .collect(Collectors.toList()));
                    });
            });

        return effectiveRoles.entrySet().stream()
            .map(x -> new AbstractMap.SimpleEntry<>(x.getKey(), new ArrayList<>(x.getValue())))
            .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    private Function<List<String>, Predicate<WebACAuthorization>> accessToClass = uris -> {
        final List<String> intersection = new ArrayList<>(uris);
        return x -> {
            intersection.retainAll(x.getAccessToClassURIs());
            return intersection.size() > 0;
        };
    };


    private Function<List<String>, Predicate<WebACAuthorization>> accessTo = uris -> {
        final List<String> intersection = new ArrayList<>(uris);
        return x -> {
            intersection.retainAll(x.getAccessToURIs());
            return intersection.size() > 0;
        };
    };

    @Override
    public void postRoles(final Node node, final Map<String, Set<String>> data)
            throws RepositoryException {
        throw new RuntimeException("postRoles() is not implemented");
    }

    @Override
    public void deleteRoles(final Node node) throws RepositoryException {
        throw new RuntimeException("deleteRoles() is not implemented");
    }

    @Override
    public Map<String, List<String>> findRolesForPath(final Path absPath, final Session session)
            throws RepositoryException {
        throw new RuntimeException("findRolesForPath() is not implemented");
    }

    final Predicate<Property> isAclPredicate =
         p -> !p.isAnon() && p.getNameSpace().startsWith(WEBAC_NAMESPACE_VALUE);

    private List<WebACAuthorization> getAuthorizations(final Node node, final String location) {
        final List<WebACAuthorization> authorizations = new ArrayList<>();
        final Model model = createDefaultModel();

        try {
            final FedoraResource resource = new FedoraResourceImpl(node.getSession().getNode(location));
            final IdentifierConverter<Resource, FedoraResource> translator =
                new DefaultIdentifierTranslator(node.getSession());

            final List<String> EMPTY = Collections.unmodifiableList(new ArrayList<>());

            resource.getChildren().forEachRemaining(child -> {
                if (child.getTypes().contains(WEBAC_AUTHORIZATION)) {
                    final Map<String, List<String>> tripleMap = new HashMap<>();
                    child.getTriples(translator, PropertiesRdfContext.class)
                         .filter(p -> isAclPredicate.test(model.asStatement(p).getPredicate()))
                         .forEachRemaining(t -> {
                            tripleMap.putIfAbsent(t.getPredicate().getURI(), new ArrayList<>());
                             if (t.getObject().isURI()) {
                                tripleMap.get(t.getPredicate().getURI()).add(t.getObject().getURI());
                             } else if (t.getObject().isLiteral()) {
                                tripleMap.get(t.getPredicate().getURI()).add(
                                    t.getObject().getLiteralValue().toString());
                             }
                         });
                    authorizations.add(new WebACAuthorizationImpl(
                                tripleMap.getOrDefault(WEBAC_AGENT_VALUE, EMPTY),
                                tripleMap.getOrDefault(WEBAC_AGENT_CLASS_VALUE, EMPTY),
                                tripleMap.getOrDefault(WEBAC_MODE_VALUE, EMPTY).stream()
                                            .map(URI::create).collect(Collectors.toList()),
                                tripleMap.getOrDefault(WEBAC_ACCESSTO_VALUE, EMPTY),
                                tripleMap.getOrDefault(WEBAC_ACCESSTO_CLASS_VALUE, EMPTY)));
                }
            });
        } catch (final RepositoryException ex) {
            throw new RepositoryRuntimeException(ex);
        }
        return authorizations;
    }

    /**
     * Find the effective ACL as a URI. It may or may not exist, and it may or may
     * not be a fedora resource.
     */
    private static Optional<URI> getEffectiveAcl(final FedoraResource resource) {
        try {
            if (resource.hasProperty(WEBAC_ACCESS_CONTROL_VALUE)) {
                return Optional.of(
                        new URI(resource.getProperty(WEBAC_ACCESS_CONTROL_VALUE).getString()));
            } else if (resource.getNode().getDepth() == 0) {
                return Optional.empty();
            } else {
                return getEffectiveAcl(resource.getContainer());
            }
        } catch (final Exception ex) {
            return Optional.empty();
        }
    }

}
