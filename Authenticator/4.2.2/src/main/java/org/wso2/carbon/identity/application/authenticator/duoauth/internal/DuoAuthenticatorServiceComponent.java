package org.wso2.carbon.identity.application.authenticator.duoauth.internal;

import java.util.Hashtable;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authenticator.duoauth.DuoAuthenticator;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * @scr.component name="identity.application.authenticator.basicauth.component" immediate="true"
 * @scr.reference name="realm.service"
 * interface="org.wso2.carbon.user.core.service.RealmService"cardinality="1..1"
 * policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 */
public class DuoAuthenticatorServiceComponent {

    private static Log log = LogFactory.getLog(DuoAuthenticatorServiceComponent.class);
    
    private static RealmService realmService;
    
    protected void activate(ComponentContext ctxt) {
    	
    	DuoAuthenticator basicAuth = new DuoAuthenticator();
    	Hashtable<String, String> props = new Hashtable<String, String>();
    	
        ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(), basicAuth, props);
        
        if (log.isDebugEnabled()) {
            log.info("DuoAuthenticator bundle is activated");
        }
    }

    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.info("DuoAuthenticator bundle is deactivated");
        }
    }
    
    protected void setRealmService(RealmService realmService) {
        log.debug("Setting the Realm Service");
        DuoAuthenticatorServiceComponent.realmService = realmService;
    }

    protected void unsetRealmService(RealmService realmService) {
        log.debug("UnSetting the Realm Service");
        DuoAuthenticatorServiceComponent.realmService = null;
    }

    public static RealmService getRealmService() {
        return realmService;
    }

}
