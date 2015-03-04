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

/**
 * Defines all the constants used by
 * FacebookAuthenticator class of custom facebook authenticator.
 *
 * @since 2014-12-08
 */
public final class FacebookAuthenticatorConstants {

	public static final String AUTHENTICATOR_NAME = "CustomFacebookAuthenticator";
	public static final String FRIENDLY_NAME = "Facebook Custom";

	public static final String OAUTH2_GRANT_TYPE_CODE = "code";
	public static final String OAUTH2_PARAM_STATE = "state";
	public static final String LOGIN_TYPE = "facebook";

	public static final String FB_AUTH_URL = "http://www.facebook.com/dialog/oauth";
	public static final String FB_TOKEN_URL = "https://graph.facebook.com/oauth/access_token";
	public static final String FB_USER_INFO_URL = "https://graph.facebook.com/me";
	public static final String SCOPE = "email";

	public static final String CLIENT_ID = "ClientId";
	public static final String CLIENT_SECRET = "ClientSecret";
	public static final String USER_IDENTIFIER_FIELD = "UserIdentifierField";
	public static final String USER_INFO_FIELDS = "UserInfoFields";

	private FacebookAuthenticatorConstants() {}
}
