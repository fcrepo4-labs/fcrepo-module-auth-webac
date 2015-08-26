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
 * AccessToClassHandler defines the interface for handling AccessToClass ACLs
 * that are managed in a pre-configured location defined by the
 * property fcrepo.auth.webac.location
 *
 * @author mohideen
 * @date 8/25/15.
 */
public interface AccessToClassHandler {

    String ACCESS_TO_CLASS_ACL_LOCATION = "fcrepo.auth.webac.location";

    /**
     * Get allowed access modes for agent based on ACLs at the configured
     * location that have matching objectTypes
     * @param objectTypes
     * @param agent
     * @return Set of allowed modes
     */
    Set<URI> getModes(final Set<RDF> objectTypes, final String agent);

    /**
     * Set allowed access modes for objectType with specified set of agents.
     * @param objectType
     * @param accessModes
     * @param agents
     */
    void setModes(final RDF objectType, final Set<URI> accessModes, final Set<String> agents);

    /**
     * Set allowed access modes for objectType with specified agent.
     * @param objectType
     * @param accessModes
     * @param agent
     */
    void setModes(final RDF objectType, final Set<URI> accessModes, final String agent);

    /**
     * Set allowed access mode for objectType with specified set of agents.
     * @param objectType
     * @param accessMode
     * @param agents
     */
    void setMode(final RDF objectType, final URI accessMode, final Set<String> agents);

    /**
     * Set allowed access mode for objectType with specified agent.
     * @param objectType
     * @param accessMode
     * @param agent
     */
    void setMode(final RDF objectType, final URI accessMode, final String agent);

    /**
     * Get all ACLs for objectType.
     * @param objectType
     * @return List of ACL objects for the objectType
     */
    List<WebAclAuthorization> getAuthorizationforType(final RDF objectType);

    /**
     * Remove all ACLs for objectType.
     * @param objectType
     */
    void removeAuthorizationforType(final RDF objectType);


}
