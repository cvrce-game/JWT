package com.jwt.config;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.jwt.service.CustomUserDetailsService;
import com.jwt.utils.JWTUtils;

@Component
public class JWTAuthenticationFilter extends OncePerRequestFilter {

	@Autowired
	JWTUtils jwtUtils;
	@Autowired
	CustomUserDetailsService customUserDetails;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		String requestTokenHeader = request.getHeader("Authorization");
		String userName = null;
		String jwtToken = null;

		if(!StringUtils.isEmpty(requestTokenHeader) && requestTokenHeader.startsWith("Bearer ")) {
			jwtToken = requestTokenHeader.substring(7);
			try {
			userName =  this.jwtUtils.extractUsername(jwtToken);
			} catch (Exception e) {
				e.printStackTrace();
			}
			if(!StringUtils.isEmpty(userName)) {
				UserDetails userDetails = this.customUserDetails.loadUserByUsername(userName);
				UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null,userDetails.getAuthorities());
				usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
			} else {
				System.out.println("Token is not valid..!!!");
			}
		}
		filterChain.doFilter(request, response);
	}
}
