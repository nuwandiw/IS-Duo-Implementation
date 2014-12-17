package org.wso2.carbon.identity.application.authenticator.duoauth;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.Random;

/**
 * Constants used by the DuoAuthenticator
 *
 */
public abstract class DuoAuthenticatorConstants{
	
	public static final String AUTHENTICATOR_NAME = "DuoAuthenticator";
	public static final String AUTHENTICATOR_FRIENDLY_NAME = "duo";
	public static final String AUTHENTICATOR_STATUS = "DuoAuthenticatorStatus";

    public static final String IKEY = "duo.integration.key";
    public static final String SKEY = "duo.secret.key";
    public static final String HOST = "duo.host";

    public static final String RAND = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    public static final String AKEY = stringGenerator();



    public static String stringGenerator(){
        StringBuilder sb = new StringBuilder(42);
        Random rnd = new Random();

        for( int i = 0; i < 42; i++ ){
            sb.append(RAND.charAt(rnd.nextInt(DuoAuthenticatorConstants.RAND.length())));
        }
        return sb.toString();
    }

    public static String getKey(String key) throws IOException {

        String resourceName = "duo.properties"; // could also be a constant
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        Properties props = new Properties();

        InputStream resourceStream = loader.getResourceAsStream(resourceName);
        props.load(resourceStream);
        return props.getProperty(key);

    }
}
