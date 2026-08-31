const path = require('path');
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const https = require('https');
const Anthropic = require('@anthropic-ai/sdk');

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize Anthropic client
const anthropic = new Anthropic({
	apiKey: process.env.ANTHROPIC_API_KEY
});

// Allow the frontend to call this API from another local origin.
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Google Web Risk API configuration
const GOOGLE_WEB_RISK_API_KEY = process.env.API_KEY;
const GOOGLE_WEB_RISK_ENDPOINT = 'https://webrisk.googleapis.com/v1/uris:search';

// Extract URLs from text
function extractURLs(text) {
	const urlPattern = /(https?:\/\/[^\s]+)/gi;
	const matches = text.match(urlPattern) || [];
	return [...new Set(matches)]; // Remove duplicates
}

// Call Google Web Risk API to check URL safety
async function checkURLSafety(url) {
	return new Promise((resolve, reject) => {
		const threatTypes = ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'];
		const queryParams = new URLSearchParams({
			uri: url,
			threatTypes: threatTypes.join(','),
			key: GOOGLE_WEB_RISK_API_KEY
		});

		const fullUrl = `${GOOGLE_WEB_RISK_ENDPOINT}?${queryParams.toString()}`;

		https.get(fullUrl, (res) => {
			let data = '';
			res.on('data', (chunk) => { data += chunk; });
			res.on('end', () => {
				try {
					const result = JSON.parse(data);
					console.log(`[Google Web Risk API] Response for URL ${url}:`, JSON.stringify(result, null, 2));
					resolve(result);
				} catch (error) {
					console.error(`[Google Web Risk API] Failed to parse response for ${url}:`, error.message);
					reject(new Error('Failed to parse API response'));
				}
			});
		}).on('error', (error) => {
			console.error(`[Google Web Risk API] Request failed for ${url}:`, error.message);
			reject(new Error(`API call failed: ${error.message}`));
		});
	});
}

// AI-powered analysis using Anthropic Claude
async function analyzeWithAI(message, detectedThreatsInfo) {
	try {
		console.log('[Claude AI] Starting AI analysis for message...');
		
		// Build context with detected threats
		let threatContext = '';
		if (detectedThreatsInfo && detectedThreatsInfo.length > 0) {
			threatContext = `\n\nExternal Security Check Results:\n`;
			detectedThreatsInfo.forEach(threat => {
				threatContext += `- URL: ${threat.url}\n  Threat Type: ${threat.threatType}\n`;
			});
		}

		// Create prompt for Claude
		const analysisPrompt = `You are a security expert analyzing suspicious messages for scam indicators. Analyze the following message and provide a detailed security assessment.

Message to analyze:
"${message}"
${threatContext}

Provide your analysis in the following JSON format (output ONLY valid JSON, no other text):
{
  "riskLevel": "Low" | "Medium" | "High",
  "riskScore": 0-100,
  "scamIndicators": ["indicator1", "indicator2", ...],
  "manipulationTactics": ["tactic1", "tactic2", ...],
  "suspiciousRequests": ["request1", "request2", ...],
  "phishingRisk": "Low" | "Medium" | "High",
  "explanation": "Detailed explanation of findings and risk assessment",
  "safetyTips": ["tip1", "tip2", "tip3", "tip4"]
}

Consider:
1. Urgency language (act now, limited time, expires, etc.)
2. Requests for sensitive info (passwords, OTPs, bank details)
3. Unexpected rewards or prizes
4. Suspicious links or attachments
5. Sender spoofing or impersonation attempts
6. Social engineering tactics
7. Any URLs flagged as malware/social engineering`;

		const response = await anthropic.messages.create({
			model: 'claude-3-5-sonnet-20241022',
			max_tokens: 1024,
			messages: [
				{
					role: 'user',
					content: analysisPrompt
				}
			]
		});

		// Extract and parse the response
		const aiResponseText = response.content[0].type === 'text' ? response.content[0].text : '';
		console.log('[Claude AI] Raw AI response:', aiResponseText);

		// Parse JSON from response
		let aiAnalysis;
		try {
			// Try to extract JSON from the response (in case there's extra text)
			const jsonMatch = aiResponseText.match(/\{[\s\S]*\}/);
			if (jsonMatch) {
				aiAnalysis = JSON.parse(jsonMatch[0]);
			} else {
				throw new Error('No JSON found in response');
			}
		} catch (parseError) {
			console.error('[Claude AI] Failed to parse AI response:', parseError.message);
			// Return null to indicate AI analysis failed, will fallback to keyword analysis
			return null;
		}

		console.log('[Claude AI] Successfully parsed AI analysis:', aiAnalysis);
		return aiAnalysis;
	} catch (error) {
		console.error('[Claude AI] Error during AI analysis:', error.message);
		console.error('[Claude AI] Error stack:', error.stack);
		// Return null to indicate AI analysis failed, existing analysis will be used
		return null;
	}
}

const suspiciousKeywords = [
	{ keyword: 'OTP', pattern: /\botp\b|one[- ]time\s+password/i, points: 20 },
	{ keyword: 'password', pattern: /\bpassword\b/i, points: 20 },
	{ keyword: 'bank', pattern: /\bbank\b/i, points: 15 },
	{ keyword: 'account', pattern: /\baccount\b/i, points: 15 },
	{ keyword: 'verify', pattern: /\bverify\b/i, points: 15 },
	{ keyword: 'urgent', pattern: /\burgent\b/i, points: 12 },
	{ keyword: 'prize', pattern: /\bprize\b/i, points: 18 },
	{ keyword: 'winner', pattern: /\bwinner\b|\bwon\b/i, points: 18 },
	{ keyword: 'payment', pattern: /\bpayment\b/i, points: 15 },
	{ keyword: 'click link', pattern: /\bclick\s+(?:the\s+)?link\b/i, points: 18 }
];

function analyzeMessage(message) {
	const detectedMatches = suspiciousKeywords.filter(({ pattern }) => pattern.test(message));
	const riskScore = Math.min(100, detectedMatches.reduce((total, match) => total + match.points, 0));
	const riskLevel = riskScore >= 60 ? 'High' : riskScore >= 30 ? 'Medium' : 'Low';
	const detectedKeywords = detectedMatches.map(({ keyword }) => keyword);
	
	let explanation = '';
	if (riskLevel === 'High') {
		explanation = 'This message contains multiple suspicious patterns commonly found in scams. Exercise extreme caution and avoid providing any personal or financial information.';
	} else if (riskLevel === 'Medium') {
		explanation = 'This message contains some suspicious elements. Verify the sender and be cautious before responding or clicking links.';
	} else {
		explanation = 'This message appears safe based on the keywords detected, but always remain vigilant.';
	}
	
	const safetyTips = riskLevel === 'High'
		? ['Do not click links or download attachments.', 'Never share OTPs, passwords or bank details.', 'Report and delete the message immediately.', 'Contact the official organization directly if needed.']
		: riskLevel === 'Medium'
			? ['Verify the sender independently before responding.', 'Do not share personal or financial information.', 'Be cautious with unexpected requests.']
			: ['Check the sender and context before responding.', 'Stay cautious with unexpected requests.', 'Verify links before clicking.'];

	return { riskLevel, riskScore, detectedKeywords, explanation, safetyTips };
}

app.get('/api/health', (req, res) => {
	res.json({ status: 'API is working' });
});

app.post('/api/analyze', async (req, res) => {
	console.log('[POST /api/analyze] Request received');
	console.log('[POST /api/analyze] Request body:', JSON.stringify(req.body));
	
	const { message, url } = req.body || {};

	// Validate input
	if (!message && !url) {
		console.error('[POST /api/analyze] Validation failed: Neither message nor url provided');
		return res.status(400).json({ error: 'Message or URL is required.' });
	}

	try {
		console.log('[POST /api/analyze] Processing analysis...');
		let detectedThreats = [];
		let urlsChecked = [];

		// Extract URLs from message if message is provided
		if (message && typeof message === 'string' && message.trim()) {
			const extractedURLs = extractURLs(message);
			urlsChecked = urlsChecked.concat(extractedURLs);
		}

		// Add URL if directly provided
		if (url && typeof url === 'string' && url.trim()) {
			urlsChecked.push(url.trim());
		}

		// Check each URL with Google Web Risk API
		if (urlsChecked.length > 0) {
			for (const checkUrl of urlsChecked) {
				try {
					console.log(`[POST /api/analyze] Checking URL: ${checkUrl}`);
					const apiResult = await checkURLSafety(checkUrl);
					
					// Extract threats from API response
					if (apiResult.threats && apiResult.threats.length > 0) {
						console.log(`[POST /api/analyze] Threats found for ${checkUrl}:`, apiResult.threats);
						for (const threat of apiResult.threats) {
							detectedThreats.push({
								url: checkUrl,
								threatType: threat.threatType || 'UNKNOWN'
							});
						}
					} else {
						console.log(`[POST /api/analyze] No threats found for ${checkUrl}`);
					}
				} catch (error) {
					console.error(`[POST /api/analyze] Error checking URL ${checkUrl}:`, error.message);
				}
			}
		}

		// Use AI analysis if available, otherwise fallback to keyword analysis
		let aiAnalysis = null;
		if (message && typeof message === 'string' && message.trim()) {
			// Try AI analysis first
			console.log('[POST /api/analyze] Attempting AI analysis...');
			aiAnalysis = await analyzeWithAI(message, detectedThreats);
		}

		// If AI analysis succeeded, use it; otherwise fallback to keyword analysis
		let analysisResult;
		if (aiAnalysis) {
			console.log('[POST /api/analyze] Using AI analysis results');
			// Map AI analysis to our response format
			analysisResult = {
				riskLevel: aiAnalysis.riskLevel || 'Low',
				riskScore: aiAnalysis.riskScore || 0,
				detectedKeywords: aiAnalysis.scamIndicators || [],
				explanation: aiAnalysis.explanation || 'Unable to analyze message.',
				safetyTips: aiAnalysis.safetyTips || [],
				aiAnalyzed: true
			};
		} else {
			console.log('[POST /api/analyze] AI analysis failed or unavailable, using keyword analysis');
			// Fallback to keyword analysis
			analysisResult = analyzeMessage(message || '');
			analysisResult.aiAnalyzed = false;
		}

		// Combine external API results with analysis
		let combinedRiskLevel = analysisResult.riskLevel;
		let combinedRiskScore = analysisResult.riskScore;

		// If Google Web Risk API found threats, escalate risk level
		if (detectedThreats.length > 0) {
			console.log('[POST /api/analyze] Escalating risk due to detected threats from Google Web Risk API');
			combinedRiskLevel = 'High';
			combinedRiskScore = Math.max(combinedRiskScore, 85);
		}

		// Prepare final response
		const response = {
			riskLevel: combinedRiskLevel,
			riskScore: combinedRiskScore,
			detectedKeywords: analysisResult.detectedKeywords,
			explanation: detectedThreats.length > 0
				? `External security check found ${detectedThreats.length} URL(s) with known threats. ${analysisResult.explanation}`
				: analysisResult.explanation,
			safetyTips: analysisResult.safetyTips,
			detectedThreats: detectedThreats.length > 0 ? detectedThreats : null,
			urlsChecked: urlsChecked.length > 0 ? urlsChecked : null,
			aiEnhanced: analysisResult.aiAnalyzed
		};

		console.log('[POST /api/analyze] Sending response with riskLevel:', combinedRiskLevel, 'detectedThreats:', detectedThreats.length, 'aiEnhanced:', analysisResult.aiAnalyzed);
		res.json(response);
	} catch (error) {
		console.error('[POST /api/analyze] Internal server error:', error.message);
		console.error('[POST /api/analyze] Error stack:', error.stack);
		res.status(500).json({ error: 'Internal server error. Please try again.' });
	}
});

app.listen(PORT, () => {
	console.log('════════════════════════════════════════════════');
	console.log(`✓ Smart Scam Analyzer API running on port ${PORT}`);
	console.log(`✓ Access at: http://localhost:${PORT}`);
	console.log(`✓ API endpoint: http://localhost:${PORT}/api/analyze`);
	console.log(`✓ Health check: http://localhost:${PORT}/api/health`);
	console.log(`✓ CORS enabled for all origins`);
	console.log('════════════════════════════════════════════════');
});
