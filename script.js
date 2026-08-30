const messageInput = document.getElementById('message-input');
const characterCount = document.getElementById('character-count');
const analyzeButton = document.getElementById('analyze-button');
const clearButton = document.getElementById('clear-button');
const emptyState = document.getElementById('empty-state');
const loadingState = document.getElementById('loading-state');
const resultContent = document.getElementById('result-content');
const riskBadge = document.getElementById('risk-badge');
const reasonsList = document.getElementById('reasons-list');
const recommendationText = document.getElementById('recommendation-text');

const warningPatterns = [
	{ pattern: /urgent|immediately|expires|act now|within \d+/i, reason: 'Uses urgency to pressure you into acting quickly.' },
	{ pattern: /password|passcode|otp|one[- ]time|pin|verification code/i, reason: 'Requests a password, PIN, OTP or other sensitive code.' },
	{ pattern: /pay|payment|fee|bank|credit card|gift card|crypto|bitcoin|transfer/i, reason: 'Mentions payment, banking details or money transfers.' },
	{ pattern: /click|link|verify|confirm|login|http|www\./i, reason: 'Asks you to click a link or verify account details.' },
	{ pattern: /won|winner|prize|reward|free|congratulations/i, reason: 'Uses an unexpected prize or reward as a hook.' }
];

messageInput.addEventListener('input', () => {
	characterCount.textContent = `${messageInput.value.length} / 3000`;
});

analyzeButton.addEventListener('click', async () => {
	const message = messageInput.value.trim();
	
	// Accept either message or URL
	if (!message) {
		messageInput.focus();
		messageInput.style.borderColor = 'var(--danger)';
		return;
	}
	
	messageInput.style.borderColor = '';
	emptyState.hidden = true;
	resultContent.hidden = true;
	loadingState.hidden = false;
	
	// Determine if input is a URL or message
	const isURL = /^https?:\/\//.test(message);
	
	// Call the Node.js API
	try {
		const requestBody = isURL 
			? { url: message }
			: { message: message };
		
		console.log('[API Request] Sending to http://localhost:3000/api/analyze:', requestBody);
		
		const response = await fetch('http://localhost:3000/api/analyze', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json'
			},
			body: JSON.stringify(requestBody)
		});

		console.log('[API Response] Status:', response.status, response.statusText);

		if (!response.ok) {
			const errorData = await response.json().catch(() => ({ error: 'Unable to parse error response' }));
			console.error('[API Error] Status', response.status, '- Details:', errorData);
			throw new Error(`API Error: ${response.status} - ${errorData.error || 'Unknown error'}`);
		}

		const result = await response.json();
		console.log('[API Success] Analysis result received:', result);
		showAPIResult(result);
	} catch (error) {
		console.error('[API Fetch Error] Failed to connect:', error.message);
		console.error('[API Fetch Error] Full error object:', error);
		showErrorResult(error);
	} finally {
		// ALWAYS hide loading state when API request completes (success or error)
		loadingState.hidden = true;
	}
});

function showAPIResult(result) {
	// Display results from the Node.js API (with external API threat data)
	const { riskLevel, riskScore, detectedKeywords, explanation, safetyTips, externalThreatData, urlsChecked, detectedThreats } = result;
	
	// Update risk badge
	riskBadge.textContent = `${riskLevel.toUpperCase()} RISK`;
	riskBadge.className = `risk-badge ${riskLevel.toLowerCase()}`;
	
	// Build detailed reasons content
	let reasonsHTML = '';
	
	// Show risk score
	reasonsHTML += `<li><strong>Risk Score:</strong> ${riskScore}/100</li>`;
	
	// Show analysis/explanation
	if (explanation) {
		reasonsHTML += `<li><strong>Analysis:</strong> ${explanation}</li>`;
	}
	
	// Show detected threats from Google Web Risk API
	if (detectedThreats && detectedThreats.length > 0) {
		reasonsHTML += '<li style="background-color: #ffe0e0; padding: 10px; border-radius: 4px; margin-bottom: 10px;"><strong style="color: #d32f2f;">🔴 SECURITY THREATS DETECTED</strong><ul>';
		for (const threat of detectedThreats) {
			reasonsHTML += `<li><strong>${threat.url}</strong><br>Threat Type: ${threat.threatType}</li>`;
		}
		reasonsHTML += '</ul></li>';
	} else if (externalThreatData && externalThreatData.length > 0) {
		// Fallback for old response format
		reasonsHTML += '<li style="background-color: #ffe0e0; padding: 10px; border-radius: 4px; margin-bottom: 10px;"><strong style="color: #d32f2f;">🔴 EXTERNAL THREAT DETECTED</strong><ul>';
		for (const threatItem of externalThreatData) {
			reasonsHTML += `<li><strong>URL:</strong> ${threatItem.url}</li>`;
			if (threatItem.threats && threatItem.threats.length > 0) {
				for (const threat of threatItem.threats) {
					reasonsHTML += `<li>Threat: ${threat.threatType || 'Unknown'}</li>`;
				}
			}
		}
		reasonsHTML += '</ul></li>';
	}
	
	// Show detected keywords if present
	if (detectedKeywords && detectedKeywords.length > 0) {
		reasonsHTML += `<li><strong>Detected Scam Keywords:</strong> ${detectedKeywords.join(', ')}</li>`;
	}
	
	// If nothing was detected, show safe message
	if (!detectedThreats || detectedThreats.length === 0) {
		if (!detectedKeywords || detectedKeywords.length === 0) {
			if (!externalThreatData || externalThreatData.length === 0) {
				reasonsHTML += '<li>No known security threat detected.</li>';
			}
		}
	}
	
	reasonsList.innerHTML = reasonsHTML;
	
	// Display safety tips
	if (safetyTips && safetyTips.length > 0) {
		const tipsContent = safetyTips.map((tip) => `<li>${tip}</li>`).join('');
		recommendationText.innerHTML = `<strong>Safety Tips:</strong><ul style="margin-top: 10px; padding-left: 20px;">${tipsContent}</ul>`;
	} else {
		recommendationText.innerHTML = '<strong>Safety Tips:</strong><ul style="margin-top: 10px; padding-left: 20px;"><li>Always verify the sender independently before responding.</li><li>Never share personal or financial information via unsolicited messages.</li></ul>';
	}
	
	resultContent.hidden = false;
}

function showErrorResult(error) {
	// Handle API errors with detailed logging
	console.error('[Error Handler] Error message:', error.message);
	console.error('[Error Handler] Full error stack:', error.stack);
	
	riskBadge.textContent = 'ERROR';
	riskBadge.className = 'risk-badge error';
	reasonsList.innerHTML = `
		<li><strong>Failed to connect to API server</strong></li>
		<li>Error: ${error.message}</li>
		<li><strong>Troubleshooting:</strong>
			<ul>
				<li>1. Check that server is running: npm start</li>
				<li>2. Verify server is on http://localhost:3000</li>
				<li>3. Open browser console (F12) to see detailed error logs above</li>
				<li>4. Check if port 3000 is in use by another process</li>
			</ul>
		</li>
	`;
	recommendationText.innerHTML = '<strong>Next steps:</strong> Ensure API server is running and try again.';
	
	resultContent.hidden = false;
}

function showResult(message) {
	const matches = warningPatterns.filter(({ pattern }) => pattern.test(message));
	const risk = matches.length >= 3 ? 'HIGH' : matches.length >= 1 ? 'MEDIUM' : 'LOW';
	const reasons = matches.length ? matches.map(({ reason }) => reason) : ['No common scam signals were found in this message.'];
	const recommendation = risk === 'HIGH'
		? 'Do not reply, click links or send money. Contact the organization through a trusted website or phone number, then report and delete the message.'
		: risk === 'MEDIUM'
			? 'Pause before responding. Verify the sender independently and avoid sharing personal details or opening links until you are certain.'
			: 'Still use your judgment. Check the sender and context independently before sharing information or taking action.';
	riskBadge.textContent = `${risk} RISK`;
	riskBadge.className = `risk-badge ${risk.toLowerCase()}`;
	reasonsList.innerHTML = reasons.map((reason) => `<li>${reason}</li>`).join('');
	recommendationText.textContent = recommendation;
	loadingState.hidden = true;
	resultContent.hidden = false;
}

clearButton.addEventListener('click', () => {
	messageInput.value = '';
	characterCount.textContent = '0 / 3000';
	messageInput.style.borderColor = '';
	loadingState.hidden = true;
	resultContent.hidden = true;
	emptyState.hidden = false;
	messageInput.focus();
});
