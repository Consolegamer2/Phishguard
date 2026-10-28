if (!window.__gmailPhisherInitialized) {
  window.__gmailPhisherInitialized = true;

(() => {
  const HIGHLIGHT_CLASS = "phisher-highlight";
  const RISK_CLASS = "phisher-risk-badge";
  const PHRASE_CLASS = "phisher-suspicious-phrase";
  const LINK_CLASS = "phisher-suspicious-link";
  const AI_PHRASE_CLASS = "phisher-ai-phrase";
  let observer = null;
  let highlightTimer = null;

  function injectStyles() {
    if (document.getElementById("phisher-highlight-style")) {
      return;
    }

    const style = document.createElement("style");
    style.id = "phisher-highlight-style";
    style.textContent = `
      .${HIGHLIGHT_CLASS} {
        background: #fff176;
        color: #000;
        padding: 0 2px;
        border-radius: 3px;
        box-shadow: inset 0 0 0 1px #f57f17;
      }

      .${RISK_CLASS} {
        display: inline-block;
        margin-left: 6px;
        padding: 2px 6px;
        border-radius: 999px;
        font-size: 11px;
        font-weight: bold;
        background: #d32f2f;
        color: white;
      }

      .${PHRASE_CLASS} {
        background: #ffe0b2;
        color: #000;
        padding: 0 2px;
        border-radius: 3px;
        border-bottom: 2px solid #e65100;
        cursor: help;
      }

      .${LINK_CLASS} {
        outline: 2px solid #d32f2f;
        outline-offset: 1px;
        border-radius: 2px;
        background: #ffebee;
      }

      .${AI_PHRASE_CLASS} {
        padding: 0 2px;
        border-radius: 3px;
        cursor: help;
        border-bottom: 2px dashed #6a1b9a;
        background: #f3e5f5;
      }

      .${AI_PHRASE_CLASS}[data-severity="high"] {
        background: #fce4ec;
        border-bottom-color: #ad1457;
      }

      .${AI_PHRASE_CLASS}[data-severity="low"] {
        background: #ede7f6;
        border-bottom-color: #5e35b1;
      }
    `;
    document.head.appendChild(style);
  }

  function removeHighlights() {
    document.querySelectorAll(`.${HIGHLIGHT_CLASS}, .${PHRASE_CLASS}`).forEach((element) => {
      const parent = element.parentNode;
      if (!parent) {
        return;
      }
      parent.replaceChild(document.createTextNode(element.textContent || ""), element);
    });
    document.querySelectorAll(`.${LINK_CLASS}`).forEach((element) => {
      element.classList.remove(LINK_CLASS);
      element.removeAttribute("title");
    });
  }

  function isSingleEmailOpen() {
    // we can test the location of inbox with this line
    return /^#[a-z]+\/[A-Za-z0-9_-]+/i.test(location.hash);
  }

  function getOpenMessageContainer() {
    if (!isSingleEmailOpen()) {
      return null;
    }

    const selectors = [
      'div[aria-label="Message Body"]',
      'div[aria-label="Message body"]',
      'div.a3s.aiL',
      'div.ii.gt'
    ];

    for (const selector of selectors) {
      const element = document.querySelector(selector);
      if (element && element.innerText.trim()) {
        return element;
      }
    }
    return null;
  }

  function getEmailBodyText() {
    // Only ever returns text from an actually-open message, never the
    // whole page — scoring risk against the whole inbox list produces
    // false positives from unrelated, harmless emails.
    const container = getOpenMessageContainer();
    return container ? container.innerText.trim() : "";
  }

  function getSenderEmail() {
    if (!isSingleEmailOpen()) {
      return null;
    }

    // Gmail tags sender/recipient chips with a real `email` attribute
    // even when the screen only shows a display name — this is far more
    // reliable than regex-matching visible text, which may never contain
    // the raw address at all. BUT `[email]` chips also show up outside the
    // open message (chat sidebar, contact hovercards, suggested contacts
    // for people you email often) — an unscoped, first-match query can
    // latch onto one of those and "stick" on a frequent contact's address
    // no matter which email is actually open. Scope to the main reading
    // pane, and take the last match (the expanded/current message in the
    // thread), not the first.
    // Scope to the main reading pane (not chat/contacts sidebars), and
    // match ONLY Gmail's sender-name class (.gD) — not a generic
    // span[email], which also matches the "to" recipient chip in the
    // header (including your own address), and would otherwise get
    // picked up as the "last" match instead of the actual sender.
    const scope = document.querySelector('div[role="main"]') || document;
    const senderNodes = scope.querySelectorAll(".gD[email]");
    if (senderNodes.length) {
      return senderNodes[senderNodes.length - 1].getAttribute("email");
    }

    const text = getEmailBodyText();
    const match = text.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
    return match ? match[0] : null;
  }

  function highlightSuspiciousPhrases(container) {
    if (!container || !window.PhishingModel?.suspiciousKeywords?.length) {
      return;
    }

    const keywords = window.PhishingModel.suspiciousKeywords
      .slice()
      .sort((a, b) => b.length - a.length) // match longer phrases first, e.g. "action required" before "action"
      .map((word) => word.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
    const phraseRegex = new RegExp(`(${keywords.join("|")})`, "gi");

    const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        const parent = node.parentElement;
        if (!parent || parent.closest(`script, style, noscript, .${HIGHLIGHT_CLASS}, .${RISK_CLASS}, .${PHRASE_CLASS}`)) {
          return NodeFilter.FILTER_REJECT;
        }
        const value = node.nodeValue || "";
        if (!value.trim() || !phraseRegex.test(value)) {
          return NodeFilter.FILTER_REJECT;
        }
        phraseRegex.lastIndex = 0;
        return NodeFilter.FILTER_ACCEPT;
      }
    });

    const textNodes = [];
    let currentNode;
    while ((currentNode = walker.nextNode())) {
      textNodes.push(currentNode);
    }

    textNodes.forEach((textNode) => {
      const text = textNode.nodeValue || "";
      const matches = [...text.matchAll(phraseRegex)];
      if (!matches.length) {
        return;
      }

      const fragment = document.createDocumentFragment();
      let lastIndex = 0;

      matches.forEach((match) => {
        const start = match.index || 0;
        const end = start + match[0].length;
        if (start > lastIndex) {
          fragment.appendChild(document.createTextNode(text.slice(lastIndex, start)));
        }

        const span = document.createElement("span");
        span.className = PHRASE_CLASS;
        span.title = "Common wording used in phishing emails";
        span.textContent = match[0];
        fragment.appendChild(span);
        lastIndex = end;
      });

      if (lastIndex < text.length) {
        fragment.appendChild(document.createTextNode(text.slice(lastIndex)));
      }

      if (textNode.parentNode) {
        textNode.parentNode.replaceChild(fragment, textNode);
      }
    });
  }

  function highlightSuspiciousLinks(container) {
    if (!container || !window.PhishingModel) {
      return;
    }

    container.querySelectorAll("a[href]").forEach((link) => {
      let domain;
      try {
        domain = new URL(link.href, location.href).hostname.toLowerCase();
      } catch (e) {
        return;
      }

      const shortened = window.PhishingModel.isShortenedDomain(domain);
      const spoofed = window.PhishingModel.isSpoofedDomain(domain);
      if (shortened || spoofed) {
        link.classList.add(LINK_CLASS);
        link.title = spoofed
          ? "This link's address looks like it's imitating a well-known company"
          : "This link uses a link-shortening service, which can hide the real destination";
      }
    });
  }

  function clearAiHighlights() {
    document.querySelectorAll(`.${AI_PHRASE_CLASS}`).forEach((element) => {
      const parent = element.parentNode;
      if (!parent) {
        return;
      }
      parent.replaceChild(document.createTextNode(element.textContent || ""), element);
    });
  }

  function highlightExactPhraseOnce(container, phrase, severity, reason) {
    if (!container || !phrase || !phrase.trim()) {
      return false;
    }

    const escaped = phrase.trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const regex = new RegExp(escaped, "i");

    const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        const parent = node.parentElement;
        if (!parent || parent.closest(`script, style, noscript, .${HIGHLIGHT_CLASS}, .${RISK_CLASS}, .${PHRASE_CLASS}, .${AI_PHRASE_CLASS}`)) {
          return NodeFilter.FILTER_REJECT;
        }
        const value = node.nodeValue || "";
        return value && regex.test(value) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
      }
    });

    const node = walker.nextNode();
    if (!node) {
      return false; // AI's phrase wasn't found verbatim in the message — skip rather than guess
    }

    const text = node.nodeValue || "";
    const match = text.match(regex);
    if (!match) {
      return false;
    }

    const start = match.index;
    const end = start + match[0].length;

    const fragment = document.createDocumentFragment();
    if (start > 0) {
      fragment.appendChild(document.createTextNode(text.slice(0, start)));
    }

    const span = document.createElement("span");
    span.className = AI_PHRASE_CLASS;
    span.dataset.severity = (severity || "medium").toLowerCase();
    span.title = reason || "Flagged by AI review";
    span.textContent = match[0];
    fragment.appendChild(span);

    if (end < text.length) {
      fragment.appendChild(document.createTextNode(text.slice(end)));
    }

    node.parentNode.replaceChild(fragment, node);
    return true;
  }

  function highlightAiFlags(flags) {
    const container = getOpenMessageContainer();
    if (!container) {
      return { applied: 0, total: Array.isArray(flags) ? flags.length : 0 };
    }

    clearAiHighlights();

    let applied = 0;
    (flags || []).forEach((flag) => {
      if (flag && highlightExactPhraseOnce(container, flag.phrase, flag.severity, flag.reason)) {
        applied += 1;
      }
    });

    return { applied, total: Array.isArray(flags) ? flags.length : 0 };
  }

  function highlightEmailMatches() {
    if (!document.body) {
      return;
    }


    observer?.disconnect();
    injectStyles();
    removeHighlights();

    // Score against the full email body so inline badges agree with the
    // risk shown in the popup, instead of scoring each short text fragment
    // (e.g. "From: name@domain.com") in isolation.
    const fullBodyText = getEmailBodyText();
    const emailRegex = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        const parent = node.parentElement;
        if (!parent || parent.closest("script, style, noscript, iframe, textarea, input")) {
          return NodeFilter.FILTER_REJECT;
        }

        const value = node.nodeValue || "";
        if (!value.trim() || !emailRegex.test(value)) {
          return NodeFilter.FILTER_REJECT;
        }

        emailRegex.lastIndex = 0;
        return NodeFilter.FILTER_ACCEPT;
      }
    });

    const textNodes = [];
    let currentNode;
    while ((currentNode = walker.nextNode())) {
      textNodes.push(currentNode);
    }

    textNodes.forEach((textNode) => {
      const text = textNode.nodeValue || "";
      const matches = [...text.matchAll(emailRegex)];
      if (!matches.length) {
        return;
      }

      const fragment = document.createDocumentFragment();
      let lastIndex = 0;

      matches.forEach((match) => {
        const start = match.index || 0;
        const end = start + match[0].length;

        if (start > lastIndex) {
          fragment.appendChild(document.createTextNode(text.slice(lastIndex, start)));
        }

        const span = document.createElement("span");
        span.className = HIGHLIGHT_CLASS;
        span.textContent = match[0];

        const risk = window.PhishingModel ? window.PhishingModel.detectRisk(fullBodyText || text) : 0.5;
        if (risk >= 0.45) {
          const badge = document.createElement("span");
          badge.className = RISK_CLASS;
          badge.textContent = window.PhishingModel ? window.PhishingModel.getRiskLabel(risk) : "unknown";
          span.appendChild(badge);
        }

        fragment.appendChild(span);
        lastIndex = end;
      });

      if (lastIndex < text.length) {
        fragment.appendChild(document.createTextNode(text.slice(lastIndex)));
      }

      if (textNode.parentNode) {
        textNode.parentNode.replaceChild(fragment, textNode);
      }
    });

    // Only within the actually-open message (not the whole page — same
    // reason getEmailBodyText is scoped this way, to avoid flagging
    // unrelated text elsewhere on the page).
    const openContainer = getOpenMessageContainer();
    if (openContainer) {
      highlightSuspiciousPhrases(openContainer);
      highlightSuspiciousLinks(openContainer);
    }

    if (observer && document.body) {
      observer.observe(document.body, {
        childList: true,
        subtree: true,
      });
    }
  }

  function getEmailFromPage() {
    return getSenderEmail();
  }

  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "getEmail") {
      highlightEmailMatches();
      sendResponse(getEmailFromPage());
      return true;
    }
    if (request.action === "getRiskScore") {
      const bodyText = request.text || request.email || getEmailBodyText() || "";
      const risk = window.PhishingModel ? window.PhishingModel.detectRisk(bodyText) : 0.5;
      const label = window.PhishingModel ? window.PhishingModel.getRiskLabel(risk) : "UNKNOWN";
      sendResponse({ risk, label });
      return true;
    }
    if (request.action === "getEmailBodyTextForAI") {
      sendResponse({ text: getEmailBodyText() });
      return true;
    }
    if (request.action === "applyAiHighlights") {
      sendResponse(highlightAiFlags(request.flags));
      return true;
    }
  });

  function init() {
    if (!document.body) {
      return;
    }

    injectStyles();
    highlightEmailMatches();

    observer = new MutationObserver(() => {
      clearTimeout(highlightTimer);
      highlightTimer = setTimeout(highlightEmailMatches, 300);
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
})();
}
