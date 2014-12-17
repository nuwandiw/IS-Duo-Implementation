package org.wso2.carbon.identity.application.authenticator.duoauth;

import com.duosecurity.duoweb.DuoWeb;
import com.duosecurity.duoweb.DuoWebException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Mobile based 2nd factor Authenticator
 * 
 */
public class DuoAuthenticator extends AbstractApplicationAuthenticator
		implements LocalApplicationAuthenticator {

	private static final long serialVersionUID = 4438354156955223654L;

	private static Log log = LogFactory.getLog(DuoAuthenticator.class);

	@Override
	public boolean canHandle(HttpServletRequest request) {

		if (request.getParameter("sig_response") != null) {
			return true;
		}
		return false;
	}

	@Override
	protected void initiateAuthenticationRequest(HttpServletRequest request,
			HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
        String username = null;

        try{

            for(int i=1; i<context.getSequenceConfig().getStepMap().size(); i++){
                if(context.getSequenceConfig().getStepMap().get(i).getAuthenticatedAutenticator().
                        getApplicationAuthenticator() instanceof LocalApplicationAuthenticator){
                    username = context.getSequenceConfig().getStepMap().get(i).getAuthenticatedUser(); //Getting the username from the last authenticated local user
                }
            }
            String sig_request = DuoWeb.signRequest(DuoAuthenticatorConstants.getKey(DuoAuthenticatorConstants.IKEY),
                    DuoAuthenticatorConstants.getKey(DuoAuthenticatorConstants.SKEY),
                    DuoAuthenticatorConstants.AKEY, username);



            response.sendRedirect(loginPage + "?authenticators=" + getName() + ":" +"LOCAL&type=duo&signreq=" +
                    sig_request + "&sessionDataKey=" + request.getParameter("sessionDataKey") +
                    "&duoHost="+DuoAuthenticatorConstants.getKey(DuoAuthenticatorConstants.HOST));

		} catch (IOException e) {
			throw new AuthenticationFailedException(e.getMessage(), e);
		}
	}

	@Override
	protected void processAuthenticationResponse(HttpServletRequest request,
			HttpServletResponse response, AuthenticationContext context)
			throws AuthenticationFailedException {

		boolean isAuthenticated = false;
        String username = null;
        boolean isDebugEnabled = log.isDebugEnabled();

		try {
            username = DuoWeb.verifyResponse(DuoAuthenticatorConstants.getKey(DuoAuthenticatorConstants.IKEY),
                    DuoAuthenticatorConstants.getKey(DuoAuthenticatorConstants.SKEY),
                    DuoAuthenticatorConstants.AKEY, request.getParameter("sig_response"));

            isAuthenticated = true;

            if(isDebugEnabled){
                log.debug("User authenticated: "+username);
            }

		} catch (DuoWebException e) {
            log.error("Duo Authentication failed while verifying");
            throw new AuthenticationFailedException(e.getMessage(),e);
        } catch (NoSuchAlgorithmException e) {
            log.error("Duo Authentication failed while verifying");
            throw new AuthenticationFailedException(e.getMessage(),e);
        } catch (InvalidKeyException e) {
            log.error("Duo Authentication failed while verifying");
            throw new AuthenticationFailedException(e.getMessage(),e);
        } catch (IOException e) {
            log.error("Duo Authentication failed while verifying");
            throw new AuthenticationFailedException(e.getMessage(),e);
        }

        if (!isAuthenticated) {
			if (log.isDebugEnabled()) {
				log.debug("user authentication failed in duo");
            }

            throw new AuthenticationFailedException();
		}

		context.setSubject(username);
	}

	
	@Override
	public String getContextIdentifier(HttpServletRequest request) {
		return request.getParameter("sessionDataKey");
	}

	@Override
	public String getFriendlyName() {
		return DuoAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
	}

	@Override
	public String getName() {
		return DuoAuthenticatorConstants.AUTHENTICATOR_NAME;
	}
}
