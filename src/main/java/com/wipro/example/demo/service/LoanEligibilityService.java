package com.wipro.example.demo.service;

import java.util.List;

import org.springframework.stereotype.Service;

import com.wipro.example.demo.soap.api.loaneligibility.Acknowledment;
import com.wipro.example.demo.soap.api.loaneligibility.CustomerRequest;

@Service
public class LoanEligibilityService {

	/**
	 * This method will check eligibility and return acknowledgement based on some
	 * conditions.
	 * 
	 * @param request
	 * @return
	 */
	public Acknowledment checkLoanEligibility(CustomerRequest request) {

		Acknowledment acknowledgement = new Acknowledment();
		List<String> mismatchCriteriaList = acknowledgement.getCriteriaMismatch();
		if (!(request.getAge() > 30 && request.getAge() < 60)) {
			mismatchCriteriaList.add("Person age should be in between 30 to 60!");
		}
		if (!(request.getYearlyIncome() > 200000)) {
			mismatchCriteriaList.add("Minimum income should be more than 200000!");
		}
		if (!(request.getCibilScore() >= 700)) {
			mismatchCriteriaList.add("Low CIBIL score, please try after 6 months!");
		}
		if (mismatchCriteriaList.size() > 0) {
			acknowledgement.setApprovedAmount(0);
			acknowledgement.setIsEligible(false);
		} else {
			acknowledgement.setApprovedAmount(500000);
			acknowledgement.setIsEligible(true);
			mismatchCriteriaList.clear();
		}
		return acknowledgement;

	}
}
