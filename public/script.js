const messageInput = document.getElementById("message-input");
const characterCount = document.getElementById("character-count");
const analyzeButton = document.getElementById("analyze-button");
const clearButton = document.getElementById("clear-button");
const emptyState = document.getElementById("empty-state");
const loadingState = document.getElementById("loading-state");
const resultSection = document.getElementById("result-section");
const resultContent = document.getElementById("result-content");
const screenshotButton = document.getElementById("screenshot-button");
const quickButtons = document.querySelectorAll(".quick-btn");

// Character Count
messageInput.addEventListener("input", () => {
    characterCount.textContent = `${messageInput.value.length} / 5000`;
});

// Quick Examples
quickButtons.forEach(button => {
    button.addEventListener("click", () => {
        const example = button.dataset.example;
        messageInput.value = example;
        characterCount.textContent = `${example.length} / 5000`;
        messageInput.focus();
    });
});

// Escape HTML
function escapeHTML(value) {
    if (value === null || value === undefined) return "";
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Risk Class
function getRiskClass(level) {
    const risk = String(level || "").toLowerCase();
    if (risk === "high") return "risk-high";
    if (risk === "medium") return "risk-medium";
    return "risk-low";
}

// Score Label
function getScoreLabel(score) {
    if (score >= 70) return "High Risk";
    if (score >= 40) return "Medium Risk";
    return "Low Risk";
}

// List Helper
function makeList(items, emptyText = "None detected") {
    if (!Array.isArray(items) || !items.length)
        return `<li>${escapeHTML(emptyText)}</li>`;

    return items.map(item => {
        if (typeof item === "object" && item !== null)
            return `<li>${escapeHTML(JSON.stringify(item))}</li>`;
        return `<li>${escapeHTML(item)}</li>`;
    }).join("");
}

// Domain Information
function renderDomainInfo(urlResults) {
    if (!Array.isArray(urlResults) || !urlResults.length) {
        return `
            <div class="info-card">
                <span class="info-icon">🌐</span>
                <div>
                    <strong>Domain Age</strong>
                    <p>No domain information available</p>
                </div>
            </div>`;
    }

    return urlResults.map(item => {
        const domain = item.domain || "Unknown";
        const ageData = item.domainAge;
        let ageText = "Unknown";
        let registeredText = "Unknown";

        if (ageData) {
            if (typeof ageData === "object") {
                if (ageData.ageYears !== undefined)
                    ageText = `${ageData.ageYears} years`;
                else if (ageData.ageDays !== undefined)
                    ageText = `${ageData.ageDays} days`;

                if (ageData.registrationDate)
                    registeredText = new Date(
                        ageData.registrationDate
                    ).toLocaleDateString();
            } else {
                ageText = String(ageData);
            }
        }

        return `
            <div class="info-card">
                <span class="info-icon">🌐</span>
                <div>
                    <strong>${escapeHTML(domain)}</strong>
                    <p>Domain Age: <b>${escapeHTML(ageText)}</b></p>
                    <p>Registered: ${escapeHTML(registeredText)}</p>
                </div>
            </div>`;
    }).join("");
}

// URL Results
function getURLList(urlResults) {
    if (!Array.isArray(urlResults) || !urlResults.length) return [];

    return urlResults.map(item =>
        item.safe
            ? `${item.url} — No known threat`
            : `${item.url} — Threat detected`
    );
}

// Render Result
function renderResult(data) {
    const score = Number(data.riskScore || 0);
    const level = data.riskLevel || getScoreLabel(score);
    const riskClass = getRiskClass(level);
    const scoreAngle = Math.min(Math.max(score, 0), 100) * 1.8;

    const detected = data.detected || {};
    const phoneNumbers = detected.phoneNumbers || [];
    const upiIds = detected.upiIds || [];
    const urls = detected.urls || [];
    const urlResults = data.urlResults || [];

    // Hugging Face AI
    const hf = data.huggingFace || {};

    const detectedThreats = urlResults.flatMap(item =>
        Array.isArray(item.threats) ? item.threats : []
    );

    const detectedKeywords = data.redFlags || [];
    const safetyTips = data.recommendations || [];
    const urlsChecked = getURLList(urlResults);

    resultContent.innerHTML = `

        <div class="result-header">
            <div>
                <p class="eyebrow">ANALYSIS RESULT</p>
                <h2>Scam Risk Assessment</h2>
            </div>
            <div class="risk-badge ${riskClass}">
                ${escapeHTML(level)}
            </div>
        </div>

        <div class="score-section">
            <div class="score-circle"
                 style="--score-angle:${scoreAngle}deg">
                <div class="score-inner">
                    <strong>${score}</strong>
                    <span>/ 100</span>
                </div>
            </div>

            <div class="score-details">
                <h3>${escapeHTML(getScoreLabel(score))}</h3>
                <p>Risk Score: <strong>${score}/100</strong></p>
                <p>
                    ${
                        score >= 70
                            ? "This content contains strong scam indicators. Be very careful."
                            : score >= 40
                            ? "This content contains some suspicious indicators. Verify before taking action."
                            : "No major scam indicators were detected, but always stay cautious."
                    }
                </p>
            </div>
        </div>

        <div class="result-grid">

            <div class="result-card">
                <h3>📱 Phone Numbers</h3>
                <ul>
                    ${makeList(phoneNumbers, "No phone number detected")}
                </ul>
            </div>

            <div class="result-card">
                <h3>💳 UPI IDs</h3>
                <ul>
                    ${makeList(upiIds, "No UPI ID detected")}
                </ul>
            </div>

            <div class="result-card">
                <h3>⚠️ Threats</h3>
                <ul>
                    ${makeList(detectedThreats, "No live threats detected")}
                </ul>
            </div>

            <div class="result-card">
                <h3>🔗 URLs Checked</h3>
                <ul>
                    ${makeList(urlsChecked, "No URL detected")}
                </ul>
            </div>

        </div>

        <div class="result-block">
            <h3>🌐 Domain Information</h3>
            <div class="info-grid">
                ${renderDomainInfo(urlResults)}
            </div>
        </div>

        <div class="result-block">
            <h3>🔎 Suspicious Keywords</h3>
            <ul class="result-list">
                ${makeList(
                    detectedKeywords,
                    "No suspicious keywords detected"
                )}
            </ul>
        </div>

        <!-- HUGGING FACE AI -->
        <div class="result-block">
            <h3>🤗 Hugging Face AI Analysis</h3>
            <ul class="result-list">
                <li>
                    Status:
                    <strong>
                        ${hf.enabled ? "Active ✅" : "Not Active ⚠️"}
                    </strong>
                </li>

                ${
                    hf.enabled
                        ? `
                    <li>
                        Model:
                        <strong>${escapeHTML(hf.model)}</strong>
                    </li>
                    <li>
                        Prediction:
                        <strong>${escapeHTML(hf.label)}</strong>
                    </li>
                    <li>
                        Confidence:
                        <strong>${escapeHTML(hf.confidencePercent)}%</strong>
                    </li>
                    <li>
                        AI Risk Score:
                        <strong>${escapeHTML(hf.riskScore)}/100</strong>
                    </li>`
                        : `
                    <li>Hugging Face model is not configured.</li>`
                }
            </ul>
        </div>

        <div class="explanation-box">
            <h3>💡 Why is this risky?</h3>
            <p>
                ${escapeHTML(
                    data.reason || "No detailed explanation available."
                )}
            </p>
        </div>

        <div class="safety-box">
            <h3>🛡️ Safety Recommendations</h3>
            <ul class="result-list">
                ${makeList(
                    safetyTips,
                    "Do not share OTP, password or banking information."
                )}
            </ul>
        </div>

        <div class="result-block">
            <h3>🔍 Detection Summary</h3>
            <ul class="result-list">
                <li>URLs detected: <strong>${urls.length}</strong></li>
                <li>Phone numbers detected: <strong>${phoneNumbers.length}</strong></li>
                <li>UPI IDs detected: <strong>${upiIds.length}</strong></li>
            </ul>
        </div>

        <div class="analysis-footer">
            <span>
                🤖 AI Enhanced:
                <strong>${data.aiEnhanced ? "Yes" : "Fallback"}</strong>
            </span>
            <span>
                🔐 ${escapeHTML(
                    data.privacy || "No database storage"
                )}
            </span>
        </div>
    `;

    emptyState.hidden = true;
    loadingState.hidden = true;
    resultSection.hidden = false;

    resultSection.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });
}

// Analyze Button
analyzeButton.addEventListener("click", async () => {
    const message = messageInput.value.trim();

    if (!message) {
        alert("Please enter a URL, phone number, UPI ID or SMS message.");
        messageInput.focus();
        return;
    }

    analyzeButton.disabled = true;
    emptyState.hidden = true;
    resultSection.hidden = true;
    loadingState.hidden = false;

    try {
        const response = await fetch("/api/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message })
        });

        const data = await response.json();

        if (!response.ok)
            throw new Error(data.error || "Analysis failed");

        console.log("API RESPONSE:", data);
        renderResult(data);

    } catch (error) {
        console.error("Analysis Error:", error);

        loadingState.hidden = true;

        resultContent.innerHTML = `
            <div class="error-box">
                <h3>❌ Analysis Failed</h3>
                <p>${escapeHTML(error.message)}</p>
                <p>Please make sure your server is running.</p>
            </div>`;

        resultSection.hidden = false;

    } finally {
        analyzeButton.disabled = false;
    }
});

// Clear Button
clearButton.addEventListener("click", () => {
    messageInput.value = "";
    characterCount.textContent = "0 / 5000";
    resultContent.innerHTML = "";
    resultSection.hidden = true;
    loadingState.hidden = true;
    emptyState.hidden = false;
    messageInput.focus();
});

// Screenshot
screenshotButton.addEventListener("click", async () => {
    if (typeof html2canvas === "undefined") {
        alert("Screenshot library is not loaded.");
        return;
    }

    try {
        const canvas = await html2canvas(resultSection, {
            backgroundColor: null,
            scale: 2,
            useCORS: true
        });

        const link = document.createElement("a");
        link.download = "smart-scam-analysis.png";
        link.href = canvas.toDataURL("image/png");
        link.click();

    } catch (error) {
        console.error("Screenshot error:", error);
        alert("Unable to create screenshot.");
    }
});