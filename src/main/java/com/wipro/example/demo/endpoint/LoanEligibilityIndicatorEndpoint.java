package com.wipro.example.demo.endpoint;

import org.opensaml.saml2.core.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ws.server.endpoint.annotation.Endpoint;
import org.springframework.ws.server.endpoint.annotation.PayloadRoot;
import org.springframework.ws.server.endpoint.annotation.RequestPayload;
import org.springframework.ws.server.endpoint.annotation.ResponsePayload;

import com.wipro.example.demo.service.LoanEligibilityService;
import com.wipro.example.demo.soap.api.loaneligibility.Acknowledment;
import com.wipro.example.demo.soap.api.loaneligibility.CustomerRequest;
import com.wipro.example.demo.validator.ResponseValidator;

@Endpoint
public class LoanEligibilityIndicatorEndpoint {

	private static final String NAMESPACE = "http://demo.example.wipro.com/soap/api/loanEligibility";

	@Autowired
	private LoanEligibilityService service;
	
	@Autowired
	private ResponseValidator responseValidator;

	@PayloadRoot(namespace = NAMESPACE, localPart = "CustomerRequest")
	@ResponsePayload
	public Acknowledment getLoanStatus(@RequestPayload CustomerRequest request,Response response) {
			
		
		boolean validationResult=false;
		try {
			 validationResult = responseValidator.validateSignature(response);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	if (validationResult) {
			return service.checkLoanEligibility(request);
		}
		return null;
	}
}
