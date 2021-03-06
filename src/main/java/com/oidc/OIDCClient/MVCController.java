package com.oidc.OIDCClient;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.TokenRevocationRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.util.URLUtils;
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
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

import net.minidev.json.JSONObject;



@RestController
public class MVCController {
	
	String clientID = "OIDCClient"; 
	String clientSecret = "secret";
	String codeCallback = "https://mucs.oidcclient.com:8003/callback/code";
	String pkceCallback = "https://mucs.oidcclient.com:8003/callback/pkce";
	String jarmCallback = "https://mucs.oidcclient.com:8003/callback/jarm";
	String OIDCTokenEndpoint = "https://cas.example.org:8443/cas/oidc/token";
	String OIDCAuthorizationEndpoint = "https://cas.example.org:8443/cas/oidc/authorize";
	String userInfoEndpoint = "https://cas.example.org:8443/cas/oidc/profile";
	String introspectionEndpoint = "https://cas.example.org:8443/cas/oidc/introspect";
	String revocationEndpoint = "https://cas.example.org:8443/cas/oidc/revoke";
	
	AccessToken accessToken = null;
	BearerAccessToken bearerAccessToken = null;
	RefreshToken refreshToken = null;
	JWT idToken = null;
	String codeChallenge = null;
	CodeVerifier codeVerifier = null;
	Nonce nonce = null;
	
	@GetMapping("/")
	public ModelAndView inicio(Model model) {
		return new ModelAndView("index");
	}
	
	@GetMapping("/login")
	public ModelAndView login() {
		return new ModelAndView("login");
	} 
	
	@GetMapping("/login/code")
	public void loginCode(HttpServletRequest request, HttpServletResponse response) {
		// The client identifier provisioned by the server

		// Generate random state string for pairing the response to the request
		//State state = new State();
		
		// Generate nonce
		this.nonce = new Nonce();

		// Compose the request (in code flow)
		AuthenticationRequest req;
		try {
			req = new AuthenticationRequest(
			    new URI(this.OIDCAuthorizationEndpoint),
			    new ResponseType("code"),
			    Scope.parse("openid email profile"),
			    new ClientID(this.clientID), // The client identifier provisioned by the server
			    new URI(this.codeCallback),
			    new State(), // Generate random state string for pairing the response to the request
			    this.nonce); // Generate nonce
			
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
	
	@GetMapping("/login/pkce")
	public void loginPKCE(HttpServletRequest request, HttpServletResponse response) {
		// Generate new random string to link the callback to the authZ request
		State state = new State();

		// Generate a new random 256 bit code verifier for PKCE
		this.codeVerifier = new CodeVerifier();

		// Build the actual OAuth 2.0 authorisation request
		AuthorizationRequest req = null;
		AuthenticationRequest req2= null;
		try {
			req = new AuthorizationRequest.Builder(
			        new ResponseType("code"), 
			        new ClientID(this.clientID))
			    .endpointURI(new URI(this.OIDCAuthorizationEndpoint))
			    .redirectionURI(URI.create(this.pkceCallback))
			    .scope(new Scope("openid email profile"))
			    .state(state)
			    .codeChallenge(this.codeVerifier, CodeChallengeMethod.S256)
			    .build();
			    
			String URIRedireccion = req.toHTTPRequest().getURL() + "?" + req.toHTTPRequest().getQuery();
			System.out.println(URIRedireccion);
			
			CodeChallenge codeChallenge = req.getCodeChallenge();
			this.codeChallenge = codeChallenge.getValue();
			System.out.println("code challenge: "+codeChallenge);
			System.out.println("code verifier: "+this.codeVerifier.getValue());
			response.sendRedirect(URIRedireccion);   
			    
			/*    
			req2 = new AuthenticationRequest.Builder(
			        new ResponseType("code"),
			        new Scope("openid email profile"),
			        new ClientID(this.clientID),
			        new URI(this.pkceCallback))
			    .endpointURI(new URI(this.OIDCAuthorizationEndpoint))
			    .state(state)
			    .codeChallenge(this.codeVerifier, CodeChallengeMethod.S256)
			    .build();
			
			String URIRedireccion = req2.toHTTPRequest().getURL() + "?" + req2.toHTTPRequest().getQuery();
			System.out.println(URIRedireccion);
			
			CodeChallenge codeChallenge = req2.getCodeChallenge();
			this.codeChallenge = codeChallenge.getValue();
			System.out.println("code challenge: "+codeChallenge);
			System.out.println("code verifier: "+this.codeVerifier.getValue());
			response.sendRedirect(URIRedireccion);*/
			
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		
	}
	
	@GetMapping("/callback/code")
	public ModelAndView callbackCode(@RequestParam(value = "code", required = false) String code,
			@RequestParam(value = "state", required = false) String state,
            HttpServletRequest request, HttpServletResponse response, Model model) {
		
		// Construct the code grant from the code obtained from the authz endpoint
		// and the original callback URI used at the authz endpoint
		AuthorizationCode authCode = new AuthorizationCode(code);
		URI callback = null;
		try {
			callback = new URI(this.codeCallback);
		} catch (URISyntaxException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		AuthorizationGrant codeGrant = new AuthorizationCodeGrant(authCode, callback);

		// The credentials to authenticate the client at the token endpoint
		ClientID clientID = new ClientID(this.clientID);
		Secret clientSecret = new Secret(this.clientSecret);
		ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);

		// The token endpoint
		URI tokenEndpoint = null;
		try {
			tokenEndpoint = new URI(this.OIDCTokenEndpoint);
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

		if (! tokenResponse.indicatesSuccess()) {
		    // We got an error response...
		    TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
		    System.out.println("error response");
		}else {
			OIDCTokenResponse successResponse = (OIDCTokenResponse)tokenResponse.toSuccessResponse();
			// Get the ID and access token, the server may also return a refresh token
			this.idToken = successResponse.getOIDCTokens().getIDToken();
			this.accessToken = successResponse.getOIDCTokens().getAccessToken();
			this.bearerAccessToken = successResponse.getOIDCTokens().getBearerAccessToken();
			this.refreshToken = successResponse.getOIDCTokens().getRefreshToken();
			
			System.out.println("idToken: "+ idToken.getParsedString());
			System.out.println("accessToken: "+ this.accessToken);
			System.out.println("refreshToken: "+ refreshToken);
			
			//model.addAttribute("IDToken", this.idToken.getParsedString());
			JSONObject at = this.accessToken.toJSONObject();
			model.addAttribute("accessToken", at.get("access_token"));
			
		}
		return new ModelAndView("index");
	}
	
	@GetMapping("/callback/pkce")
	public ModelAndView callbackPKCE(@RequestParam(value = "code", required = false) String code,
			@RequestParam(value = "state", required = false) String state,
            HttpServletRequest request, HttpServletResponse response) {
		System.out.println("CALLBACK PKCE");
		
		// Make the token request, with PKCE
		TokenRequest tokenRequest = null;
		try {
			tokenRequest = new TokenRequest(
			    new URI(this.OIDCTokenEndpoint),
			    new ClientID(this.clientID),
			    new AuthorizationCodeGrant(
			    		new AuthorizationCode(code),
			    		new URI(this.pkceCallback),
			    		this.codeVerifier));
			
			//System.out.println("url: "+tokenRequest.toHTTPRequest().getURI());
			//System.out.println("query: "+tokenRequest.toHTTPRequest().getQuery());

		} catch (URISyntaxException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		/*
		TokenResponse tokenResponse = null;
		try {
			tokenResponse = OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest().send());
		} catch (ParseException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}*/
			
			//////////////MANU//////////////
			HTTPRequest requesttemp = tokenRequest.toHTTPRequest();
			Map<String, List<String>> params = requesttemp.getQueryParameters();
			params.put("client_secret", Collections.singletonList(this.clientSecret));
			//params.put("code_verifier", Collections.singletonList(this.codeVerifier.getValue()));
			requesttemp.setQuery(URLUtils.serializeParameters(params));
			System.out.println("REQUEST TEMP: "+ requesttemp.getURL() + "?"+ requesttemp.getQuery());
			TokenResponse tokenResponse = null;
			
			HTTPResponse respuesta;
			try {
				respuesta = requesttemp.send();
				JSONObject jO = respuesta.getContentAsJSONObject();
	            tokenResponse = OIDCTokenResponseParser.parse(jO);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (ParseException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
            
			//////////////////////////////

		if (! tokenResponse.indicatesSuccess()) {
		    // We got an error response...
		    TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
		    System.out.println("error response");
		    System.out.println(errorResponse.toErrorResponse());
		}else {
			OIDCTokenResponse successResponse = (OIDCTokenResponse)tokenResponse.toSuccessResponse();
			// Get the ID and access token, the server may also return a refresh token
			this.idToken = successResponse.getOIDCTokens().getIDToken();
			this.accessToken = successResponse.getOIDCTokens().getAccessToken();
			this.bearerAccessToken = successResponse.getOIDCTokens().getBearerAccessToken();
			this.refreshToken = successResponse.getOIDCTokens().getRefreshToken();
			
			System.out.println("idToken: "+ idToken);
			System.out.println("accessToken: "+ this.accessToken);
			System.out.println("refreshToken: "+ this.refreshToken);
		}
		return new ModelAndView("index");
	}
	
	@GetMapping("/userInfo")
	public ModelAndView getUserInfo(Model model) {
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
		
		model.addAttribute("name", attributes.get("name"));
		model.addAttribute("email", attributes.get("email"));
		model.addAttribute("email_verified", attributes.get("email_verified"));
		model.addAttribute("given_name", attributes.get("given_name"));
		model.addAttribute("family_name", attributes.get("family_name"));
		model.addAttribute("picture", attributes.get("picture"));
		model.addAttribute("accessToken", this.accessToken);
		model.addAttribute("refreshToken", this.refreshToken);
		
		return new ModelAndView("profile");
	} 
	
	@GetMapping("/refreshTokens")
	public String refreshTokens(Model model) {
		
		HTTPResponse respuesta = null;
		TokenResponse tokenResponse = null;
		try {
			HTTPRequest  req = new HTTPRequest(HTTPRequest.Method.POST, 
					new URL(this.OIDCTokenEndpoint+"?"+
							"grant_type=refresh_token"+
							"&client_id="+this.clientID+
							"&client_secret="+this.clientSecret+
							"&refresh_token="+this.refreshToken));
			
			respuesta = req.send();
			JSONObject jO = respuesta.getContentAsJSONObject();
            tokenResponse = OIDCTokenResponseParser.parse(jO);
			
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		if (! tokenResponse.indicatesSuccess()) {
		    // We got an error response...
		    TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
		    return "Error";
		}else {
			OIDCTokenResponse successResponse = (OIDCTokenResponse)tokenResponse.toSuccessResponse();
			// Get the ID and access token, the server may also return a refresh token
			JWT idToken = successResponse.getOIDCTokens().getIDToken();
			this.accessToken = successResponse.getOIDCTokens().getAccessToken();
			this.bearerAccessToken = successResponse.getOIDCTokens().getBearerAccessToken();
			this.refreshToken = successResponse.getOIDCTokens().getRefreshToken();
			
			JSONObject objectResponse = new JSONObject();
			objectResponse.put("accessToken",this.accessToken.getValue());
			objectResponse.put("refreshToken",this.refreshToken);
			
			return objectResponse.toJSONString();
			 
		}
	}
	
	@GetMapping("/verificarToken")
	public boolean verificarToken(@RequestParam(value = "accesstoken", required = false) String accessToken) {
		
		try {
			TokenIntrospectionRequest req = new TokenIntrospectionRequest(
					new URI(this.introspectionEndpoint),
					new ClientSecretBasic(new ClientID(this.clientID), new Secret(this.clientSecret)),
					new BearerAccessToken(accessToken));
			
			HTTPResponse resp = req.toHTTPRequest().send();
            JSONObject jsResp= resp.getContentAsJSONObject();

            return (boolean) jsResp.get("active");
			
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;		
		
	}
	
	@GetMapping("/revocarTokens")
	public void revocarToken() {
		
		try {
			TokenRevocationRequest req = new TokenRevocationRequest(
					new URI(this.revocationEndpoint),
					new ClientSecretBasic(new ClientID(this.clientID), new Secret(this.clientSecret)),
					this.bearerAccessToken);
			
			req.toHTTPRequest().send();
			
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}		
		
	}
	
	@GetMapping("/logout")
	public ModelAndView logout(@RequestParam(value = "logout", required = false) String logout, HttpServletResponse response) {
		if(logout==null) {
			return new ModelAndView("logout");
		}else{
			
			System.out.println("logout="+logout);
			HTTPRequest req;
			try {
				req = new HTTPRequest(HTTPRequest.Method.GET, 
						new URL(this.revocationEndpoint));
				req.send();
				
			} catch (MalformedURLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			this.idToken=null;
			this.accessToken=null;
			this.bearerAccessToken=null;
			this.refreshToken=null;
			this.codeChallenge=null;
			this.codeVerifier=null;
			this.nonce=null;
			
			if(logout.equalsIgnoreCase("service")) {
				return new ModelAndView("index");
			}else {
				String URIRedireccion = "https://cas.example.org:8443/cas/logout?service=https://mucs.oidcclient.com:8003";
				try {
					response.sendRedirect(URIRedireccion);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				return null;
			}	
		}
		
		
	}
	
	@GetMapping("/isSignedOn")
	public boolean isSignedOn(HttpSession session) {
		if(this.accessToken!=null)
			return true;
		else
			return false;
	}
	
	@RequestMapping(method = RequestMethod.POST
	        , consumes = {"application/x-www-form-urlencoded"}
	        ,value = "/sessionended"
	)
	public
	@ResponseBody
	String createXXXX(HttpSession session, @RequestBody MultiValueMap params) throws Exception {
	    System.out.println("params are " + params);
	    //session.invalidate();
	    return "hello";
	}
}
