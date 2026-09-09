const path = require('path');
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const https = require('https');
const Anthropic = require('@anthropic-ai/sdk');
const { InferenceClient } = require('@huggingface/inference');

const app = express();
const PORT = process.env.PORT || 3000;

// =====================================================
// ANTHROPIC AI
// =====================================================

const anthropic = new Anthropic({
    apiKey: process.env.ANTHROPIC_API_KEY
});

// =====================================================
// HUGGING FACE AI
// =====================================================

const hfClient = process.env.HF_TOKEN
    ? new InferenceClient(process.env.HF_TOKEN)
    : null;

const HF_MODEL =
    'ealvaradob/bert-finetuned-phishing';

// =====================================================
// MIDDLEWARE
// =====================================================

app.use(cors());

app.use(
    express.json({
        limit: '100kb'
    })
);

app.use(
    express.static(
        path.join(__dirname, 'public')
    )
);

// =====================================================
// GOOGLE WEB RISK API
// =====================================================

const GOOGLE_WEB_RISK_API_KEY =
    process.env.API_KEY;

const GOOGLE_WEB_RISK_ENDPOINT =
    'https://webrisk.googleapis.com/v1/uris:search';

// =====================================================
// EXTRACT URLS
// =====================================================

function extractURLs(text) {

    const regex =
        /https?:\/\/[^\s]+/gi;

    return text.match(regex) || [];
}

// =====================================================
// EXTRACT PHONE NUMBERS
// =====================================================

function extractPhoneNumbers(text) {

    const regex =
        /(?:\+91[\s-]?)?[6-9]\d{9}\b/g;

    return text.match(regex) || [];
}

// =====================================================
// EXTRACT UPI IDs
// =====================================================

function extractUPIIds(text) {

    const regex =
        /\b[a-zA-Z0-9._-]{2,}@[a-zA-Z]{2,}\b/g;

    return text.match(regex) || [];
}

// =====================================================
// GET DOMAIN
// =====================================================

function getDomainFromURL(url) {

    try {

        return new URL(url).hostname;

    } catch (error) {

        return null;
    }
}

// =====================================================
// DOMAIN AGE USING RDAP
// =====================================================

function getDomainAge(domain) {

    return new Promise((resolve) => {

        if (!domain) {
            resolve(null);
            return;
        }

        function requestRDAP(url, redirects = 0) {

            if (redirects > 5) {
                console.error(
                    `Too many RDAP redirects for ${domain}`
                );

                resolve(null);
                return;
            }

            https.get(
                url,
                {
                    headers: {
                        'User-Agent':
                            'Smart-Scam-Analyzer/1.0',

                        'Accept':
                            'application/rdap+json, application/json'
                    }
                },
                (res) => {

                    // =====================================
                    // FOLLOW REDIRECT
                    // =====================================

                    if (
                        res.statusCode >= 300 &&
                        res.statusCode < 400 &&
                        res.headers.location
                    ) {

                        const redirectURL =
                            new URL(
                                res.headers.location,
                                url
                            ).toString();

                        res.resume();

                        requestRDAP(
                            redirectURL,
                            redirects + 1
                        );

                        return;
                    }

                    let data = '';

                    res.on(
                        'data',
                        chunk => {
                            data += chunk;
                        }
                    );

                    res.on(
                        'end',
                        () => {

                            if (res.statusCode !== 200) {

                                console.error(
                                    `RDAP failed for ${domain}: HTTP ${res.statusCode}`
                                );

                                resolve(null);
                                return;
                            }

                            try {

                                const result =
                                    JSON.parse(data);

                                const events =
                                    Array.isArray(
                                        result.events
                                    )
                                        ? result.events
                                        : [];

                                const registrationEvent =
                                    events.find(
                                        event =>
                                            event.eventAction ===
                                            'registration'
                                    );

                                if (
                                    !registrationEvent ||
                                    !registrationEvent.eventDate
                                ) {

                                    resolve(null);
                                    return;
                                }

                                const registrationDate =
                                    new Date(
                                        registrationEvent.eventDate
                                    );

                                if (
                                    isNaN(
                                        registrationDate.getTime()
                                    )
                                ) {

                                    resolve(null);
                                    return;
                                }

                                const now =
                                    new Date();

                                const ageDays =
                                    Math.floor(
                                        (
                                            now -
                                            registrationDate
                                        ) /
                                        (
                                            1000 *
                                            60 *
                                            60 *
                                            24
                                        )
                                    );

                                const ageYears =
                                    Math.floor(
                                        ageDays / 365
                                    );

                                resolve({

                                    registrationDate:
                                        registrationDate.toISOString(),

                                    ageDays,

                                    ageYears,

                                    registered: true

                                });

                            } catch (error) {

                                console.error(
                                    `RDAP JSON error for ${domain}`
                                );

                                resolve(null);
                            }
                        }
                    );
                }
            ).on(
                'error',
                () => {

                    console.error(
                        `RDAP request failed for ${domain}`
                    );

                    resolve(null);
                }
            );
        }

        const rdapURL =
            `https://rdap.org/domain/${encodeURIComponent(domain)}`;

        requestRDAP(rdapURL);
    });
}
                    

// =====================================================
// GOOGLE WEB RISK CHECK
// =====================================================

function checkURLSafety(url) {

    return new Promise((resolve) => {

        if (!GOOGLE_WEB_RISK_API_KEY) {

            resolve({

                safe: true,

                checked: false,

                threats: []

            });

            return;
        }

        const apiURL =
            `${GOOGLE_WEB_RISK_ENDPOINT}` +
            `?key=${encodeURIComponent(
                GOOGLE_WEB_RISK_API_KEY
            )}` +
            `&uri=${encodeURIComponent(url)}` +
            `&threatTypes=MALWARE` +
            `&threatTypes=SOCIAL_ENGINEERING`;

        https.get(
            apiURL,
            (res) => {

                let data = '';

                res.on(
                    'data',
                    chunk => {
                        data += chunk;
                    }
                );

                res.on(
                    'end',
                    () => {

                        try {

                            const result =
                                JSON.parse(data);

                            const threats =
                                result.threat ||
                                result.threatTypes ||
                                [];

                            resolve({

                                safe:
                                    threats.length === 0,

                                checked: true,

                                threats

                            });

                        } catch (error) {

                            resolve({

                                safe: true,

                                checked: false,

                                threats: []

                            });
                        }
                    }
                );
            }
        ).on(
            'error',
            () => {

                resolve({

                    safe: true,

                    checked: false,

                    threats: []

                });
            }
        );
    });
}

// =====================================================
// HUGGING FACE AI ANALYSIS
// =====================================================

async function analyzeWithHuggingFace(message) {

    if (!hfClient) {

        return {

            enabled: false,

            label: null,

            confidence: 0,

            riskScore: 0

        };
    }

    try {

        const result =
            await hfClient.textClassification({

                model: HF_MODEL,

                inputs: message

            });

        let predictions = result;

        if (
            Array.isArray(result) &&
            Array.isArray(result[0])
        ) {

            predictions =
                result[0];
        }

        if (
            !Array.isArray(predictions) ||
            predictions.length === 0
        ) {

            return {

                enabled: false,

                label: null,

                confidence: 0,

                riskScore: 0

            };
        }

        const bestPrediction =
            [...predictions].sort(
                (a, b) =>
                    Number(b.score || 0) -
                    Number(a.score || 0)
            )[0];

        const label =
            String(
                bestPrediction.label || ''
            );

        const confidence =
            Number(
                bestPrediction.score || 0
            );

        const lowerLabel =
            label.toLowerCase();

        const isPhishing =
            lowerLabel.includes('phish') ||
            lowerLabel.includes('scam') ||
            lowerLabel.includes('malicious') ||
            lowerLabel.includes('fraud') ||
            lowerLabel === '1';

        let riskScore = 0;

        if (isPhishing) {

            riskScore =
                Math.round(
                    confidence * 100
                );

        } else {

            riskScore =
                Math.round(
                    (1 - confidence) * 40
                );
        }

        riskScore =
            Math.max(
                0,
                Math.min(
                    100,
                    riskScore
                )
            );

        return {

            enabled: true,

            label,

            confidence,

            riskScore

        };

    } catch (error) {

        console.error(
            'Hugging Face analysis failed:',
            error.message
        );

        return {

            enabled: false,

            label: null,

            confidence: 0,

            riskScore: 0

        };
    }
}

// =====================================================
// ANTHROPIC AI ANALYSIS
// =====================================================

async function analyzeWithAI(message) {

    if (!process.env.ANTHROPIC_API_KEY) {

        return null;
    }

    try {

        const response =
            await anthropic.messages.create({

                model:
                    'claude-3-5-sonnet-latest',

                max_tokens: 800,

                messages: [

                    {

                        role: 'user',

                        content: `
You are a cybersecurity scam detection assistant.

Analyze the following message and return ONLY valid JSON.

Required format:

{
  "riskScore": number,
  "riskLevel": "Low" | "Medium" | "High",
  "reason": "short explanation",
  "redFlags": ["red flag 1", "red flag 2"],
  "recommendations": ["recommendation 1", "recommendation 2"]
}

Risk score:
0-39 = Low
40-69 = Medium
70-100 = High

Look for:
- OTP requests
- Password requests
- Bank details
- UPI/payment requests
- Fake rewards
- Urgency
- Threats
- Account blocking
- Suspicious links
- KYC requests
- Refund scams
- Impersonation
- Phishing

Message:

${message}
`
                    }
                ]
            });

        const text =
            response.content?.[0]?.text ||
            '';

        const cleaned =
            text
                .replace(
                    /```json/gi,
                    ''
                )
                .replace(
                    /```/g,
                    ''
                )
                .trim();

        return JSON.parse(cleaned);

    } catch (error) {

        console.error(
            'AI analysis failed:',
            error.message
        );

        return null;
    }
}

// =====================================================
// FALLBACK KEYWORD ANALYSIS
// =====================================================

function analyzeMessage(message) {

    const lowerMessage =
        message.toLowerCase();

    const suspiciousKeywords = [

        'otp',
        'password',
        'bank',
        'account',
        'verify',
        'urgent',
        'prize',
        'winner',
        'payment',
        'upi',
        'kyc',
        'click link',
        'refund',
        'blocked',
        'blocked account',
        'claim',
        'reward'

    ];

    const foundKeywords =
        suspiciousKeywords.filter(
            keyword =>
                lowerMessage.includes(
                    keyword
                )
        );

    let riskScore = 0;

    riskScore +=
        foundKeywords.length * 8;

    if (
        lowerMessage.includes('otp') ||
        lowerMessage.includes('password')
    ) {

        riskScore += 20;
    }

    if (
        lowerMessage.includes('urgent') ||
        lowerMessage.includes('immediately') ||
        lowerMessage.includes('now')
    ) {

        riskScore += 15;
    }

    if (
        lowerMessage.includes('prize') ||
        lowerMessage.includes('winner') ||
        lowerMessage.includes('reward')
    ) {

        riskScore += 15;
    }

    if (
        lowerMessage.includes('blocked') ||
        lowerMessage.includes(
            'account will be'
        )
    ) {

        riskScore += 15;
    }

    riskScore =
        Math.min(
            100,
            riskScore
        );

    let riskLevel =
        'Low';

    if (riskScore >= 70) {

        riskLevel =
            'High';

    } else if (riskScore >= 40) {

        riskLevel =
            'Medium';
    }

    const recommendations = [

        'Do not share OTP or passwords.',

        'Do not make payments to unknown people.',

        'Verify the sender independently.',

        'Avoid opening suspicious links.'

    ];

    return {

        riskScore,

        riskLevel,

        reason:
            foundKeywords.length > 0
                ? 'Suspicious keywords and scam-like patterns were detected.'
                : 'No major scam indicators were detected.',

        redFlags:
            foundKeywords,

        recommendations

    };
}

// =====================================================
// HEALTH CHECK
// =====================================================

app.get(
    '/api/health',
    (req, res) => {

        res.json({

            status:
                'API is working',

            huggingFace:
                Boolean(
                    process.env.HF_TOKEN
                )

        });
    }
);

// =====================================================
// HOME PAGE
// =====================================================

app.get(
    '/',
    (req, res) => {

        res.sendFile(
            path.join(
                __dirname,
                'public',
                'index.html'
            )
        );
    }
);

// =====================================================
// MAIN ANALYZE API
// =====================================================

app.post(
    '/api/analyze',
    async (req, res) => {

        try {

            const message =
                typeof req.body?.message === 'string'
                    ? req.body.message.trim()
                    : '';

            if (!message) {

                return res.status(400).json({

                    error:
                        'Message is required'

                });
            }

            // =========================================
            // DETECT INPUTS
            // =========================================

            const urls =
                extractURLs(message);

            const phoneNumbers =
                extractPhoneNumbers(message);

            const upiIds =
                extractUPIIds(message);

            // =========================================
            // URL ANALYSIS
            // =========================================

            const urlResults = [];

            for (const url of urls) {

                const domain =
                    getDomainFromURL(url);

                const safety =
                    await checkURLSafety(url);

                const domainAge =
                    await getDomainAge(domain);

                urlResults.push({

                    url,

                    domain,

                    safe:
                        safety.safe,

                    checked:
                        safety.checked,

                    threats:
                        safety.threats,

                    domainAge

                });
            }

            // =========================================
            // HUGGING FACE ANALYSIS
            // =========================================

            const huggingFaceAnalysis =
                await analyzeWithHuggingFace(
                    message
                );

            // =========================================
            // CLAUDE AI ANALYSIS
            // =========================================

            const aiAnalysis =
                await analyzeWithAI(
                    message
                );

            // =========================================
            // FALLBACK ANALYSIS
            // =========================================

            const fallbackAnalysis =
                analyzeMessage(
                    message
                );

            const finalAnalysis =
                aiAnalysis ||
                fallbackAnalysis;

            // =========================================
            // INITIAL RISK SCORE
            // =========================================

            let finalRiskScore =
                Number(
                    finalAnalysis.riskScore
                ) || 0;

            let finalRiskLevel =
                finalAnalysis.riskLevel ||
                'Low';

            // =========================================
            // HUGGING FACE RISK
            // =========================================

            if (
                huggingFaceAnalysis.enabled
            ) {

                finalRiskScore =
                    Math.round(

                        (
                            finalRiskScore *
                            0.60
                        ) +

                        (
                            huggingFaceAnalysis.riskScore *
                            0.40
                        )
                    );
            }

            // =========================================
            // LIVE URL THREATS
            // =========================================

            const detectedThreats =
                urlResults.flatMap(
                    item =>
                        item.threats || []
                );

            if (
                detectedThreats.length > 0
            ) {

                finalRiskScore =
                    Math.max(
                        finalRiskScore,
                        90
                    );

                finalRiskLevel =
                    'High';
            }

            // =========================================
            // URL DETECTED
            // =========================================

            if (
                urls.length > 0 &&
                detectedThreats.length === 0
            ) {

                finalRiskScore =
                    Math.max(
                        finalRiskScore,
                        20
                    );
            }

            // =========================================
            // UPI DETECTED
            // =========================================

            if (
                upiIds.length > 0
            ) {

                finalRiskScore =
                    Math.max(
                        finalRiskScore,
                        25
                    );
            }

            // =========================================
            // PHONE DETECTED
            // =========================================

            if (
                phoneNumbers.length > 0
            ) {

                finalRiskScore =
                    Math.max(
                        finalRiskScore,
                        20
                    );
            }

            // =========================================
            // FINAL SCORE
            // =========================================

            finalRiskScore =
                Math.min(
                    100,
                    Math.max(
                        0,
                        finalRiskScore
                    )
                );

            // =========================================
            // FINAL RISK LEVEL
            // =========================================

            if (
                finalRiskScore >= 70
            ) {

                finalRiskLevel =
                    'High';

            } else if (
                finalRiskScore >= 40
            ) {

                finalRiskLevel =
                    'Medium';

            } else {

                finalRiskLevel =
                    'Low';
            }

            // =========================================
            // RESPONSE
            // =========================================

            res.json({

                success: true,

                riskScore:
                    finalRiskScore,

                riskLevel:
                    finalRiskLevel,

                reason:
                    finalAnalysis.reason,

                redFlags:
                    finalAnalysis.redFlags || [],

                recommendations:
                    finalAnalysis.recommendations || [],

                detected: {

                    urls,

                    phoneNumbers,

                    upiIds

                },

                urlResults,

                huggingFace: {

                    enabled:
                        huggingFaceAnalysis.enabled,

                    model:
                        HF_MODEL,

                    label:
                        huggingFaceAnalysis.label,

                    confidence:
                        huggingFaceAnalysis.confidence,

                    confidencePercent:
                        Math.round(
                            (
                                huggingFaceAnalysis.confidence ||
                                0
                            ) * 100
                        ),

                    riskScore:
                        huggingFaceAnalysis.riskScore

                },

                privacy:
                    'No data is stored permanently. No login required.'

            });

        } catch (error) {

            console.error(
                'Analyze API error:',
                error.message
            );

            res.status(500).json({

                success: false,

                error:
                    'Unable to analyze the message.'

            });
        }
    }
);

// =====================================================
// START SERVER
// =====================================================

app.listen(
    PORT,
    () => {

        console.log(
            `Smart Scam Analyzer running on port ${PORT}`
        );

    }
);