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

import java.security.Principal;

import javax.servlet.http.HttpServletRequest;

import org.fcrepo.auth.common.FedoraAuthorizationDelegate;

import org.junit.Test;
import org.mockito.Mock;

/**
 * @author mohideen
 * @since 9/1/15.
 */
public class FedoraWebACUserSecurityContextTest {

    @Mock
    private FedoraAuthorizationDelegate fad;
    @Mock
    private Principal principal;
    @Mock
    private HttpServletRequest request;

    @Test
    public void testHasRole() {
    }

}
