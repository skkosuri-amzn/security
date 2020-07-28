/*
 *   Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License").
 *   You may not use this file except in compliance with the License.
 *   A copy of the License is located at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   or in the "license" file accompanying this file. This file is distributed
 *   on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *   express or implied. See the License for the specific language governing
 *   permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.auth;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.user.User;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;

import static com.amazon.opendistroforelasticsearch.security.support.ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES;
import static org.junit.Assert.assertEquals;
import org.junit.Test;


public class RolesInjectorTest {

    @Test
    public void testDisabled() {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        RolesInjector rolesInjector = new RolesInjector(threadContext);

        assertEquals(false, rolesInjector.isRoleInjected());
        User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        assertEquals(null, user);
        assertEquals(null, rolesInjector.getInjectedRoles());
    }

    @Test
    public void testEnabledAndInjected() {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        threadContext.putTransient(OPENDISTRO_SECURITY_INJECTED_ROLES, "user1|role_1,role_2");

        RolesInjector rolesInjector = new RolesInjector(threadContext);
        assertEquals(true, rolesInjector.isRoleInjected());
        User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        assertEquals("user1", user.getName());
        assertEquals(0, user.getRoles().size());
        assertEquals(2, rolesInjector.getInjectedRoles().size());
        assertEquals(true, rolesInjector.getInjectedRoles().contains("role_1"));
        assertEquals(true, rolesInjector.getInjectedRoles().contains("role_2"));
    }
}
