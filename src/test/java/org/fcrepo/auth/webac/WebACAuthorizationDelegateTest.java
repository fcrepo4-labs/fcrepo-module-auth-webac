package org.fcrepo.auth.webac;

import static org.junit.Assert.assertFalse;

import java.util.HashSet;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.modeshape.jcr.api.Session;

public class WebACAuthorizationDelegateTest {

	private WebACAuthorizationDelegate webacAD;
	
    @Mock
    private Session mockSession;
	
	@Before
	public void setUp() {
		webacAD = new WebACAuthorizationDelegate();
	}
	
	@Test
	public void test() {
		assertFalse(webacAD.rolesHavePermission(mockSession, "/fake/path", getFakeActions(), getFakeRoles()));
	}

    private static String[] getFakeActions() {
        final String[] fakeActions =  new String[2];
        fakeActions[0] = "fakeAction1";
        fakeActions[1] = "fakeAction2";
        return fakeActions;
    }

    private static Set<String> getFakeRoles() {
        final Set<String> fakeRoles = new HashSet<>();
        fakeRoles.add("fakeRole1");
        fakeRoles.add("fakeRole2");
        return fakeRoles;
    }
}
