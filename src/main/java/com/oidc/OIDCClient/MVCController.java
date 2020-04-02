package com.oidc.OIDCClient;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import net.minidev.json.JSONObject;



@RestController
public class MVCController {
	
	String OIDCClientID = "OIDCClient"; 
	String secret = "secret";
	String callback = "http://mucs.oidcclient.com:8003/callback";
	String tokenEndpoint = "https://cas.example.org:8443/cas/oidc/token";
	String authorizationEndpoint = "https://cas.example.org:8443/cas/oidc/authorize";
	String userInfoEndpoint = "https://cas.example.org:8443/cas/oidc/profile";
	AccessToken accessToken = null;
	BearerAccessToken bearerAccessToken = null;
	
	/*@GetMapping("/CASlogin")
	public ModelAndView redirectWithUsingRedirectPrefix(ModelMap model) {
        model.addAttribute("service", "http://localhost:8000");
        return new ModelAndView("redirect:/https://cas.example.org/cas/login", model);
    }*/
	
	
	@GetMapping("/greeting")
	public String greeting(@RequestParam(name="name", required=false, defaultValue="World") String name, Model model) {
		model.addAttribute("name", name);
		return "greeting";
	} 
	
	@GetMapping("/")
	public ModelAndView inicio(Model model) {
		return new ModelAndView("index");
	}
	
	@GetMapping("/login/code")
	public void login(HttpServletRequest request, HttpServletResponse response) {
		// The client identifier provisioned by the server
		ClientID clientID = new ClientID(this.OIDCClientID);

		// Generate random state string for pairing the response to the request
		State state = new State();

		// Generate nonce
		Nonce nonce = new Nonce();

		// Compose the request (in code flow)
		AuthenticationRequest req;
		try {
			req = new AuthenticationRequest(
			    new URI(this.authorizationEndpoint),
			    new ResponseType("code"),
			    Scope.parse("openid email profile"),
			    clientID,
			    new URI(this.callback),
			    state,
			    nonce);
			
			String URIRedireccion = req.toHTTPRequest().getURL() + "?" + req.toHTTPRequest().getQuery();
			response.sendRedirect(URIRedireccion);
			/*HTTPResponse httpResponse = req.toHTTPRequest().send();

			AuthenticationResponse response = AuthenticationResponseParser.parse(httpResponse);

			if (response instanceof AuthenticationErrorResponse) {
			    // process error
				System.out.println("error en la autenticacion");
			}

			AuthenticationSuccessResponse successResponse =
			    (AuthenticationSuccessResponse)response;

			// Retrieve the authorisation code
			AuthorizationCode code = successResponse.getAuthorizationCode();

			// Don't forget to check the state
			assert successResponse.getState().equals(state);*/
			
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		
	}
	
	@GetMapping("/callback/code")
	public ModelAndView callback(@RequestParam(value = "code", required = false) String code,
			@RequestParam(value = "state", required = false) String state,
            HttpServletRequest request, HttpServletResponse response) {
		
		System.out.println(code);
		System.out.println(state);
		
		// Construct the code grant from the code obtained from the authz endpoint
		// and the original callback URI used at the authz endpoint
		AuthorizationCode authCode = new AuthorizationCode(code);
		URI callback = null;
		try {
			callback = new URI(this.callback);
		} catch (URISyntaxException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		AuthorizationGrant codeGrant = new AuthorizationCodeGrant(authCode, callback);

		// The credentials to authenticate the client at the token endpoint
		ClientID clientID = new ClientID(this.OIDCClientID);
		Secret clientSecret = new Secret(this.secret);
		ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);

		// The token endpoint
		URI tokenEndpoint = null;
		try {
			tokenEndpoint = new URI(this.tokenEndpoint);
		} catch (URISyntaxException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		// Make the token request
		TokenRequest tokenRequest = new TokenRequest(tokenEndpoint, clientAuth, codeGrant);

		TokenResponse tokenResponse = null;
		try {
			tokenResponse = OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest().send());
		} catch (ParseException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		if(tokenResponse == null)
			System.out.println("response null");
		
		if (! tokenResponse.indicatesSuccess()) {
		    // We got an error response...
		    TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
		    System.out.println("error response");
		    System.out.println(errorResponse);
		}else {
			OIDCTokenResponse successResponse = (OIDCTokenResponse)tokenResponse.toSuccessResponse();
			// Get the ID and access token, the server may also return a refresh token
			JWT idToken = successResponse.getOIDCTokens().getIDToken();
			this.accessToken = successResponse.getOIDCTokens().getAccessToken();
			this.bearerAccessToken = successResponse.getOIDCTokens().getBearerAccessToken();
			RefreshToken refreshToken = successResponse.getOIDCTokens().getRefreshToken();
			
			System.out.println("idToken: "+ idToken);
			System.out.println("accessToken: "+ this.accessToken);
			System.out.println("refreshToken: "+ refreshToken);
		}
		return new ModelAndView("callback");
	}
	
	@GetMapping("/info")
	public String getUserInfo(Model model) {
		// Make the request
		HTTPResponse httpResponse = null;
		UserInfoResponse userInfoResponse = null;

		try {
			httpResponse = new UserInfoRequest(new URI(this.userInfoEndpoint), this.bearerAccessToken)
			    .toHTTPRequest()
			    .send();

			userInfoResponse = UserInfoResponse.parse(httpResponse);
				
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 

		// Parse the response
		if (! userInfoResponse.indicatesSuccess()) {
		    // The request failed, e.g. due to invalid or expired token
		    System.out.println(userInfoResponse.toErrorResponse().getErrorObject().getCode());
		    System.out.println(userInfoResponse.toErrorResponse().getErrorObject().getDescription());
		    System.out.println("Error obteniendo la info");
		}

		// Extract the claims
		UserInfo userInfo = userInfoResponse.toSuccessResponse().getUserInfo();
		System.out.println("Subject: " + userInfo.getSubject());
		System.out.println("client_id: " + userInfo.getClaim("client_id"));
		System.out.println("service: " + userInfo.getClaim("service"));
		
		JSONObject attributes = (JSONObject) userInfo.getClaim("attributes");
		System.out.println("Email: " + attributes.get("email"));
		System.out.println("Email verified: " + attributes.get("email_verified"));
		System.out.println("Given name: " + attributes.get("given_name"));
		System.out.println("Family name: " + attributes.get("family_name"));
		System.out.println("Name: " + attributes.get("name"));
		System.out.println("Picture: " + attributes.get("picture"));
		
		return "greeting";
	} 
	
}
