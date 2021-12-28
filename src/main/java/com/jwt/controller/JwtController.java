package com.jwt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.jwt.model.JWTRequest;
import com.jwt.model.JWTResponse;
import com.jwt.service.CustomUserDetailsService;
import com.jwt.utils.JWTUtils;

@RestController
public class JwtController {

	@Autowired
	AuthenticationManager authenticationManager;
	@Autowired
	CustomUserDetailsService customUserDetailsService;
	@Autowired
	JWTUtils jwtUtils;

	@RequestMapping("/hello")
	public String welcome() {
		return "Hi Welcome!!!";
	}

	@RequestMapping(value = "/token", method = RequestMethod.POST)
	public ResponseEntity<?> getToken(@RequestBody JWTRequest request) {
		try {
			this.authenticationManager
					.authenticate(new UsernamePasswordAuthenticationToken(request.getUseName(), request.getPassword()));
		} catch (Exception e) {
			e.printStackTrace();
			throw new UsernameNotFoundException("Invalid UserName And Password");
		}
		UserDetails userDetails = this.customUserDetailsService.loadUserByUsername(request.getUseName());

		String token = this.jwtUtils.generateToken(userDetails);
		return ResponseEntity.ok(new JWTResponse(token));
	}
}
