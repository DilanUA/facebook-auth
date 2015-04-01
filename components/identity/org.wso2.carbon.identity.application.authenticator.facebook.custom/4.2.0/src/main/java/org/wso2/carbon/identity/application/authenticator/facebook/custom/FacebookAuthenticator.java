/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.facebook.custom;

import org.apache.amber.oauth2.client.request.OAuthClientRequest;
import org.apache.amber.oauth2.client.response.OAuthAuthzResponse;
import org.apache.amber.oauth2.common.exception.OAuthProblemException;
import org.apache.amber.oauth2.common.exception.OAuthSystemException;
import org.apache.amber.oauth2.common.utils.JSONUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.codehaus.jettison.json.JSONException;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.ui.CarbonUIUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Implements a custom Facebook Authenticator for WSO2 Identity Server,
 * that would pass user information to some third-party application
 * based on the specified fields from the UI under federated authenticators.
 *
 * @since 2014-12-08
 */
public class FacebookAuthenticator extends AbstractApplicationAuthenticator implements
                                                       		FederatedApplicationAuthenticator {

	private static final Log log = LogFactory.getLog(FacebookAuthenticator.class);
	private static final long serialVersionUID = 1L;

	// Variables to store User Input for Authenticator properties are as follows.
	private String clientId;
	private String clientSecret;
	private String userIdentifierField;
	private String userInfoFields;

	/**
	 * Retrieve Authentication Configuration Information from IDP level.
	 *
	 * @param context Authentication context data including the relying party and etc
	 * @throws AuthenticatorException
	 */
	private void retrieveAuthenticationConfiguration(AuthenticationContext context) throws AuthenticatorException {
		Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
		clientId = authenticatorProperties.get(FacebookAuthenticatorConstants.CLIENT_ID);
		if (StringUtils.isEmpty(clientId)) {
			throw new AuthenticatorException("Client ID is empty inside Facebook authenticator configuration");
		}
		clientSecret = authenticatorProperties.get(FacebookAuthenticatorConstants.CLIENT_SECRET);
		if (StringUtils.isEmpty(clientSecret)) {
			throw new AuthenticatorException("Client Secret is empty inside Facebook authenticator configuration");
		}
		userIdentifierField = authenticatorProperties.get(FacebookAuthenticatorConstants.USER_IDENTIFIER_FIELD);
		if (StringUtils.isEmpty(userIdentifierField)) {
			throw new AuthenticatorException("User Identifier is empty inside Facebook authenticator configuration");
		}
		userInfoFields = authenticatorProperties.get(FacebookAuthenticatorConstants.USER_INFO_FIELDS);
		if (!StringUtils.isEmpty(userInfoFields)) {
			// to remove any unwanted spaces in between comma-separated field names.
			userInfoFields = userInfoFields.replaceAll("\\s", "");
		}
	}

	/**
	 * Returns true or false based on the status of handling an authentication request to Facebook.
	 *
	 * @param request Request as a HttpServletRequest type object
	 * @return A boolean Returns true if request can be handled, otherwise false
	 */
	@Override
	public boolean canHandle(HttpServletRequest request) {
		if (log.isDebugEnabled()) {
			log.debug("Inside FacebookAuthenticator.canHandle()");
		}
		return (request.getParameter(FacebookAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE) != null &&
		        request.getParameter(FacebookAuthenticatorConstants.OAUTH2_PARAM_STATE) != null &&
		        FacebookAuthenticatorConstants.LOGIN_TYPE.equals(getLoginType(request)));
	}

	/**
	 * Initiates Facebook authentication request.
	 *
	 * @param request  Request to be set as a HttpServletRequest type object
	 * @param response Response to be set as a HttpServletRequest type object
	 * @param context  Authentication context data including the relying party and etc
	 * @throws AuthenticationFailedException Custom exception type defined at authentication framework level
	 */
	@Override
	protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
	                                             AuthenticationContext context) throws AuthenticationFailedException {
		try {
			retrieveAuthenticationConfiguration(context);
			String authorizationEP = FacebookAuthenticatorConstants.FB_AUTH_URL;
			String scope = FacebookAuthenticatorConstants.SCOPE;

			String callbackUrl = CarbonUIUtil.getAdminConsoleURL(request);
			callbackUrl = callbackUrl.replace("commonauth/carbon/", "commonauth");

			String state = context.getContextIdentifier() + "," + FacebookAuthenticatorConstants.LOGIN_TYPE;

			OAuthClientRequest authRequest = OAuthClientRequest.
					                 authorizationLocation(authorizationEP).
					                 setClientId(clientId).
					                 setRedirectURI(callbackUrl).
					                 setResponseType(FacebookAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE).
					                 setScope(scope).setState(state).
					                 buildQueryMessage();
			response.sendRedirect(authRequest.getLocationUri());
		} catch (AuthenticatorException e) {
			String errorMsg = "Invalid Configuration at Facebook Authentication Wizard.";
			log.error(errorMsg, e);
			throw new AuthenticationFailedException(errorMsg, e);
		} catch (IOException e) {
			String errorMsg = "Exception while sending to the login page.";
			log.error(errorMsg, e);
			throw new AuthenticationFailedException(errorMsg, e);
		} catch (OAuthSystemException e) {
			String errorMsg = "Exception while building authorization code request.";
			log.error(errorMsg, e);
			throw new AuthenticationFailedException(errorMsg, e);
		}
	}

	/**
	 * Processes Facebook authentication response and build claims to be used by a third party application.
	 *
	 * @param request  Request made as a HttpServletRequest type object
	 * @param response Response as a HttpServletRequest type object
	 * @param context  Authentication context data including the relying party and etc
	 * @throws AuthenticationFailedException Custom exception type defined at authentication framework level
	 */
	@Override
	protected void processAuthenticationResponse(HttpServletRequest request,
	                                             HttpServletResponse response, AuthenticationContext context)
						     throws AuthenticationFailedException {
		if (log.isDebugEnabled()) {
			log.debug("Inside FacebookAuthenticator.processAuthenticationResponse()");
		}
		try {
			String tokenEndPointUrl =
				FacebookAuthenticatorConstants.FB_TOKEN_URL;
			String fbAuthUserInfoUrl =
				FacebookAuthenticatorConstants.FB_USER_INFO_URL;
			String callbackUrl = 
				CarbonUIUtil.getAdminConsoleURL(request).replace("commonauth/carbon/", "commonauth");

			String code = getAuthorizationCode(request);
			String token = getToken(tokenEndPointUrl, clientId, clientSecret, callbackUrl, code);
			
			if (log.isDebugEnabled()) {
				log.debug(String.format("Using user identifier field: %s", userIdentifierField));
			}

			Map<String, Object> userInfoJson = getUserInfoJson(fbAuthUserInfoUrl, userInfoFields, token);
			setSubject(context, userInfoJson, userIdentifierField);
			buildClaims(context, userInfoJson);
		} catch (AuthenticatorException e) {
			String errorMsg = "Failed to process Authentication Response.";
			log.error(errorMsg, e);
			throw new AuthenticationFailedException(errorMsg, e);
		}
	}

	/**
	 * Returns an authorization code to obtain an access token from Facebook.
	 *
	 * @param request Request as a HttpServletRequest type object
	 * @return A string object
	 * @throws AuthenticatorException Custom exception type for FacebookAuthenticator class
	 */
	private String getAuthorizationCode(HttpServletRequest request) throws AuthenticatorException {
		OAuthAuthzResponse authResponse;
		try {
			authResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
		} catch (OAuthProblemException e) {
			throw new AuthenticatorException("Exception while reading authorization code.", e);
		}
		return authResponse.getCode();
	}

	/**
	 * Returns an access token to retrieve Facebook user profile information.
	 *
	 * @param tokenEndPoint Facebook URL to get access token
	 * @param clientId      Client id retrieved from Facebook
	 * @param clientSecret  Client secret retrieved from Facebook
	 * @param callbackUrl   Callback URL to return
	 * @param code          Authorization code to obtain an access token from Facebook
	 * @return A string object
	 * @throws AuthenticatorException Custom exception type for FacebookAuthenticator class
	 */
	private String getToken(String tokenEndPoint, String clientId, String clientSecret,
	                        String callbackUrl, String code) throws AuthenticatorException {
		OAuthClientRequest tokenRequest = buildTokenRequest(tokenEndPoint, clientId, clientSecret, callbackUrl, code);
		String token = sendRequest(tokenRequest.getLocationUri());
		if (token.startsWith("{")) {
			if (log.isDebugEnabled()) {
				log.debug("Received token: " + token + " for code: " + code);
			}
			throw new AuthenticatorException("Received access token is invalid.");
		}
		return token;
	}

	/**
	 * Returns a token request to be made to get Facebook access token.
	 *
	 * @param tokenEndPoint Facebook URL to get access token
	 * @param clientId      Client id retrieved from Facebook
	 * @param clientSecret  Client secret retrieved from Facebook
	 * @param callbackUrl   Callback URL to return
	 * @param code          Authorization code to obtain an access token from Facebook
	 * @return An OAuthClientRequest type object
	 * @throws AuthenticatorException Custom exception type for FacebookAuthenticator class
	 */
	private OAuthClientRequest buildTokenRequest(String tokenEndPoint, String clientId,
	                                             String clientSecret, String callbackUrl, String code)
										throws AuthenticatorException {
		OAuthClientRequest tokenRequest;
		try {
			tokenRequest = OAuthClientRequest.
				       tokenLocation(tokenEndPoint).
				       setClientId(clientId).
				       setClientSecret(clientSecret).
				       setRedirectURI(callbackUrl).
				       setCode(code).buildQueryMessage();
		} catch (OAuthSystemException e) {
			throw new AuthenticatorException("Exception while building access token request.", e);
		}
		return tokenRequest;
	}

	/**
	 * Returns requested data of a Facebook user in the form of a JSON.
	 *
	 * @param fbAuthUserInfoUrl URL to get user profile information from facebook
	 * @param fields            Specific fields to be retrieved on user profile information
	 * @param token             Access token to get user profile information
	 * @return A JSON object
	 * @throws AuthenticatorException Custom exception type for FacebookAuthenticator class
	 */
	private Map<String, Object> getUserInfoJson(String fbAuthUserInfoUrl, String fields, String token)
										throws AuthenticatorException {
		Map<String, Object> jsonObject;
		String userInfoString = getUserInfoString(fbAuthUserInfoUrl, fields, token);
		try {
			jsonObject = JSONUtils.parseJSON(userInfoString);
		} catch (JSONException e) {
			if (log.isDebugEnabled()) {
				log.debug("UserInfoString: " + userInfoString, e);
			}
			throw new AuthenticatorException("Could not parse user information.", e);
		}
		return jsonObject;
	}

	/**
	 * Returns the requested data of a Facebook user in the form of a string.
	 *
	 * @param fbAuthUserInfoUrl URL to get user profile information from facebook
	 * @param fields            Specific fields to be retrieved on user profile information
	 * @param token             Access token to get user profile information
	 * @return A string object
	 * @throws AuthenticatorException Custom exception type for FacebookAuthenticator class
	 */
	private String getUserInfoString(String fbAuthUserInfoUrl, String fields, String token)
			throws AuthenticatorException {
		String userInfoString;
		if (StringUtils.isEmpty(fields) || fields == null) {
			userInfoString = sendRequest(String.format("%s?%s", fbAuthUserInfoUrl, token));
		} else {
			userInfoString = sendRequest(String.format("%s?fields=%s&%s", fbAuthUserInfoUrl, fields, token));
		}
		return userInfoString;
	}

	/**
	 * Set Facebook user identifier value as the subject of authentication context data.
	 *
	 * @param context             Authentication context data including the relying party and etc
	 * @param userInfoJson        Requested user information in the form of a JSON
	 * @param userIdentifierField User identifier field as specified in the UI
	 */
	private void setSubject(AuthenticationContext context, Map<String, Object> userInfoJson,
	                        String userIdentifierField) throws AuthenticatorException {
		String authenticatedUserId = (String) userInfoJson.get(userIdentifierField);
		if (StringUtils.isEmpty(authenticatedUserId)) {
			throw new AuthenticatorException("Authenticated user identifier value is empty.");
		}
		context.setSubject(authenticatedUserId);
	}

	/**
	 * Build claims to be used by a third party application.
	 *
	 * @param context    Authentication context data including the relying party and etc
	 * @param jsonObject Requested user information in the form of a JSON
	 * @throws AuthenticatorException Custom exception type for FacebookAuthenticator class
	 */
	private void buildClaims(AuthenticationContext context,
	                        Map<String, Object> jsonObject) throws AuthenticatorException {
		if (jsonObject != null) {
			Map<ClaimMapping, String> claims = new HashMap<ClaimMapping, String>();
			for (Map.Entry<String, Object> entry : jsonObject.entrySet()) {
				claims.put(ClaimMapping.build(entry.getKey(), entry.getKey(), null, false),
				           entry.getValue().toString());
				log.info("Adding claim mapping: " + entry.getKey() + " <> " +
				         entry.getKey() + " : " + entry.getValue());
				if (log.isDebugEnabled()) {
					log.debug("Adding claim mapping: " + entry.getKey() + " <> " +
					          entry.getKey() + " : " + entry.getValue());
				}
			}
			context.setSubjectAttributes(claims);
		} else {
			if (log.isDebugEnabled()) {
				log.debug("Decoded json object is null.");
			}
			throw new AuthenticatorException("Decoded json object is null.");
		}
	}

	/**
	 * Returns the response data of a request as a string.
	 *
	 * @param url URL to which a request should be sent
	 * @return A string object
	 * @throws AuthenticatorException Custom exception type for FacebookAuthenticator class
	 */
	private String sendRequest(String url) throws AuthenticatorException {
		StringBuilder responseData = new StringBuilder();
		BufferedReader in = null;
		try {
			URLConnection urlConnection = new URL(url).openConnection();
			in = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
			String inputLine = in.readLine();
			while (inputLine != null) {
				responseData.append(inputLine).append("\n");
				inputLine = in.readLine();
			}
		} catch (IOException e) {
			throw new AuthenticatorException("IOException while sending user information request.", e);
		} finally {
			if (in != null) {
				try {
					in.close();
				} catch (IOException e) {
					log.error("IOException while closing input stream.", e);
				}
			}
		}
		return responseData.toString();
	}

	/**
	 * Returns the context identifier extracted out from request state.
	 *
	 * @param request Request as a HttpServletRequest type object
	 * @return A string object
	 */
	@Override
	public String getContextIdentifier(HttpServletRequest request) {
		if (log.isDebugEnabled()) {
			log.debug("Inside FacebookAuthenticator.getContextIdentifier()");
		}
		String state = request.getParameter(FacebookAuthenticatorConstants.OAUTH2_PARAM_STATE);
		if (state != null) {
			return state.split(",")[0];
		} else {
			return null;
		}
	}

	/**
	 * Returns login type of the request.
	 *
	 * @param request Request as a HttpServletRequest type object
	 * @return A string object
	 */
	private String getLoginType(HttpServletRequest request) {
		String state = request.getParameter(FacebookAuthenticatorConstants.OAUTH2_PARAM_STATE);
		if (state != null) {
			return state.split(",")[1];
		} else {
			return null;
		}
	}

	/**
	 * Returns the friendly name of custom authenticator for Facebook.
	 *
	 * @return A string object
	 */
	@Override
	public String getFriendlyName() {
		return FacebookAuthenticatorConstants.FRIENDLY_NAME;
	}

	/**
	 * Returns the name of the custom authenticator for Facebook.
	 *
	 * @return A string object
	 */
	@Override
	public String getName() {
		return FacebookAuthenticatorConstants.AUTHENTICATOR_NAME;
	}

	/**
	 * Returns the user interface settings of Facebook Custom Authenticator.
	 *
	 * @return A List type object
	 */
	@Override
	public List<Property> getConfigurationProperties() {
		List<Property> configProperties = new ArrayList<Property>();

		Property clientId = new Property();
		clientId.setName(FacebookAuthenticatorConstants.CLIENT_ID);
		clientId.setDisplayName("Client Id");
		clientId.setRequired(true);
		clientId.setDescription("Enter Facebook client identifier value.");
		configProperties.add(clientId);

		Property clientSecret = new Property();
		clientSecret.setName(FacebookAuthenticatorConstants.CLIENT_SECRET);
		clientSecret.setDisplayName("Client Secret");
		clientSecret.setRequired(true);
		clientSecret.setConfidential(true);
		clientSecret.setDescription("Enter Facebook client secret value.");
		configProperties.add(clientSecret);

		Property userIdentifier = new Property();
		userIdentifier.setName(FacebookAuthenticatorConstants.USER_IDENTIFIER_FIELD);
		userIdentifier.setDisplayName("User Identifier Field");
		userIdentifier.setDescription("Enter Facebook user identifier field.");
		userIdentifier.setDefaultValue("id");
		userIdentifier.setRequired(true);
		configProperties.add(userIdentifier);

		Property userInfoFields = new Property();
		userInfoFields.setName(FacebookAuthenticatorConstants.USER_INFO_FIELDS);
		userInfoFields.setDisplayName("User Information Fields");
		userInfoFields.setDescription("Enter comma-separated Facebook user information fields.");
		userInfoFields.setRequired(false);
		configProperties.add(userInfoFields);

		return configProperties;
	}
}
