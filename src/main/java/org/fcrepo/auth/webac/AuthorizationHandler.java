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

import java.net.URI;
import java.util.Set;

import com.hp.hpl.jena.vocabulary.RDF;

/**
 * AuthorizationHandler defines the interface for configuring and retrieving
 * WebAC authorization of fedora objects.
 *
 * @author mohideen
 * @date 8/25/15.
 */
public interface AuthorizationHandler {


    /**
     * Get authorizations that have both accessTo
     * @param aclPath Path of acl to get authorizations.
     * @param resourcePath Path of the resource requested by user. (ACL: accessTo)
     * @param objectTypes rdf:type values of the resource. (ACL: accessToClass)
     * @param agent (user or group) (ACL: agent)
     * @return Set of applicable authorizations for the agent on the resource from the specified acl path.
     */
    Set<WebACAuthorization> getAuthorizations(final String aclPath, final String resourcePath, final Set<RDF> objectTypes, final String agent);

    /**
     * Get authorizations that have both accessTo
     * @param resource Resource requested by user.
     * @param agent (user or group) (ACL: agent)
     * @return Set of applicable authorizations for the agent on the resource.
     */
    Set<WebACAuthorization> getAuthorizations(final FedoraResource resource, final String agent);

    /**
     * Add allowed access modes for resource with specified set of agents.
     * @param aclPath Path of existing acl resource
     * @param resourcePath Path of fedora resource (ACL: accessTo)
     * @param accessModes Modes of access to be allowed. (ACL: mode)
     * @param agents (user or group) (ACL: agent)
     */
    void addAuthorizations(final String aclPath, final String resourcePath, final Set<URI> accessModes, final Set<String> agents);

    /**
     * Add allowed access modes for objectTypes with specified set of agents.
     * @param aclPath Path of existing acl resource
     * @param objectTypes rdf:type values of the resource. (ACL: accessToClass)
     * @param accessModes Modes of access to be allowed. (ACL: mode)
     * @param agents (user or group) (ACL: agent)
     */
    void addAuthorizations(final String aclPath, final Set<RDF> objectTypes, final Set<URI> accessModes, final Set<String> agents);

    /**
     * Replace allowed access modes for resource with specified set of agents.
     * @param aclPath Path of existing acl resource
     * @param resourcePath Path of fedora resource (ACL: accessTo)
     * @param accessModes Modes of access to be allowed. (ACL: mode)
     * @param agents (user or group) (ACL: agent)
     */
    void replaceAuthorizations(final String aclPath, final String resourcePath, final Set<URI> accessModes, final Set<String> agents);

    /**
     * Replace allowed access modes for objectTypes with specified set of agents.
     * @param aclPath Path of existing acl resource
     * @param objectTypes rdf:type values of the resource. (ACL: accessToClass)
     * @param accessModes Modes of access to be allowed. (ACL: mode)
     * @param agents (user or group) (ACL: agent)
     */
    void replaceAuthorizations(final String aclPath, final Set<RDF> objectTypes, final Set<URI> accessModes, final Set<String> agents);

    /**
     * Remove allowed access modes for objectTypes with specified set of agents.
     * @param aclPath Path of existing acl resource
     * @param resourcePath Path of fedora resource (ACL: accessTo)
     * @param agents (user or group) (ACL: agent)
     */
    void removeAuthorizations(final String aclPath, final String resourcePath, final Set<String> agents);

    /**
     * Remove allowed access modes for objectTypes with specified set of agents.
     * @param aclPath Path of existing acl resource
     * @param objectTypes rdf:type values of the resource. (ACL: accessToClass)
     * @param agents (user or group) (ACL: agent)
     */
    void removeAuthorizations(final String aclPath, final Set<RDF> objectTypes, final Set<String> agents);

    /**
     * Remove allowed access modes for objectTypes with specified set of agents.
     * @param aclPath Path of existing acl resource
     * @param resourcePath Path of fedora resource (ACL: accessTo)
     */
    void removeResourceAuthorizations(final String aclPath, final String resourcePath);

    /**
     * Remove allowed access modes for objectTypes with specified set of agents.
     * @param aclPath Path of existing acl resource
     * @param objectTypes rdf:type values of the resource. (ACL: accessToClass)
     */
    void removeTypeAuthorizations(final String aclPath, final Set<RDF> objectTypes);

    /**
     * Remove allowed access modes for objectTypes with specified set of agents.
     * @param aclPath Path of existing acl resource
     * @param agent (user or group) (ACL: agent)
     */
    void removeAgentAuthorizations(final String aclPath, final String agent);



}
