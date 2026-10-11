// Simple phishing detection model using pattern matching and heuristics
// This runs on-device, no external API needed

window.PhishingModel = (() => {
  const suspiciousKeywords = [
    { word: "verify", weight: 1.2 },
    { word: "urgent", weight: 1.0 },
    { word: "click here", weight: 1.5 },
    { word: "confirm", weight: 1.0 },
    { word: "account", weight: 0.8 },
    { word: "password", weight: 1.3 },
    { word: "reset", weight: 0.9 },
    { word: "security", weight: 0.7 },
    { word: "login", weight: 1.1 },
    { word: "update", weight: 0.8 },
    { word: "action required", weight: 1.4 },
    { word: "claim", weight: 1.2 },
    { word: "prize", weight: 1.3 },
    { word: "free", weight: 0.9 },
    { word: "alert", weight: 1.0 },
    { word: "suspended", weight: 1.4 },
    { word: "limited time", weight: 1.1 },
    { word: "act now", weight: 1.2 },
    { word: "unlock", weight: 1.0 },
    { word: "validate", weight: 1.1 }
  ];

  const suspiciousDomains = [
    "bit.ly", "goo.gl", "short.link", "tinyurl", "t.co", "ow.ly"
  ];

  const trustedDomains = [
    "google.com", "gmail.com", "amazon.com", "apple.com", "microsoft.com", 
    "paypal.com", "facebook.com", "twitter.com", "linkedin.com"
  ];

  function detectRisk(text) {
    if (!text || typeof text !== "string") {
      return 0;
    }

    const lowerText = text.toLowerCase();
    let riskScore = 0;

    // Check for suspicious keywords
    suspiciousKeywords.forEach(({ word, weight }) => {
      if (lowerText.includes(word)) {
        riskScore += weight;
      }
    });

    // Check for suspicious URLs
    const urlRegex = /https?:\/\/([^\s/$.?#].[^\s]*)/gi;
    const urls = text.match(urlRegex) || [];
    urls.forEach((url) => {
      let domain;
      try {
        domain = new URL(url).hostname.toLowerCase();
      } catch (e) {
        // Malformed URL (e.g. trailing punctuation caught by the regex) —
        // skip domain-based checks for this one instead of crashing.
        return;
      }

      // Penalize shorteners
      suspiciousDomains.forEach((suspicious) => {
        if (domain.includes(suspicious)) {
          riskScore += 2.0;
        }
      });

      // Reward trusted domains
      trustedDomains.forEach((trusted) => {
        if (domain.includes(trusted)) {
          riskScore = Math.max(0, riskScore - 0.5);
        }
      });

      // Check for domain spoofing (e.g., goog1e.com instead of google.com)
      if (/\b(g[o0]o[o0]gle|paypa1|amaz[o0]n|appie|microsift)\b/.test(domain)) {
        riskScore += 2.5;
      }
    });

    // Check for urgency + suspicious links combination
    if ((lowerText.includes("urgent") || lowerText.includes("action required")) && urls.length > 0) {
      riskScore += 1.0;
    }

    // Check for requests for sensitive data
    if (/(?:password|ssn|credit card|card number|cvv|pin|banking|wire transfer)/i.test(lowerText)) {
      riskScore += 1.5;
    }

    // Normalize to 0-1 range
    return Math.min(1.0, riskScore / 10);
  }

  function getRiskLabel(score) {
    if (score >= 0.7) {
      return "⚠️ HIGH RISK";
    }
    if (score >= 0.4) {
      return "⚠️ MEDIUM RISK";
    }
    return "✓ LOW RISK";
  }

  function isSpoofedDomain(domain) {
    return /\b(g[o0]o[o0]gle|paypa1|amaz[o0]n|appie|microsift)\b/.test(domain);
  }

  function isShortenedDomain(domain) {
    return suspiciousDomains.some((suspicious) => domain.includes(suspicious));
  }

  return {
    detectRisk,
    getRiskLabel,
    // Exposed so content.js can highlight the exact phrases/links driving
    // a score instead of only showing the final percentage.
    suspiciousKeywords: suspiciousKeywords.map(({ word }) => word),
    isSpoofedDomain,
    isShortenedDomain
  };
})();