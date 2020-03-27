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

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;


@RestController
public class MVCController {
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
	
	@GetMapping("/login")
	public void login(HttpServletRequest request, HttpServletResponse response) {
		// The client identifier provisioned by the server
		ClientID clientID = new ClientID("OIDCClient");

		// Generate random state string for pairing the response to the request
		State state = new State();

		// Generate nonce
		Nonce nonce = new Nonce();

		// Compose the request (in code flow)
		AuthenticationRequest req;
		try {
			req = new AuthenticationRequest(
			    new URI("https://cas.example.org:8443/cas/oidc/authorize"),
			    new ResponseType("code"),
			    Scope.parse("openid email profile"),
			    clientID,
			    new URI("http://mucs.oidcclient.com:8003/callback"), // The client callback URL
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
	
	@GetMapping("/callback")
	public ModelAndView callback(@RequestParam(value = "code", required = false) String code,
			@RequestParam(value = "state", required = false) String state,
            HttpServletRequest request, HttpServletResponse response) {
		
		System.out.println(code);
		System.out.println(state);
		
		return new ModelAndView("callback");
	}
	
}
