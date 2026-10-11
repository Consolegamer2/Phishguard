document.addEventListener("DOMContentLoaded", () => {
  const emailElement = document.getElementById("email");
  const riskElement = document.getElementById("risk");
  const statusElement = document.getElementById("status");
  const resultBox = document.getElementById("result");
  const refreshButton = document.getElementById("refresh-btn");
  const imageInput = document.getElementById("scam-image");
  const screenshotPreview = document.getElementById("screenshot-preview");
  const scanImageButton = document.getElementById("scan-image-btn");
  const imageStatus = document.getElementById("image-status");
  const imageResult = document.getElementById("image-result");
  const imageRisk = document.getElementById("image-risk");
  const imageExtractedText = document.getElementById("image-extracted-text");
  const aiExplainButton = document.getElementById("ai-explain-btn");
  const aiStatus = document.getElementById("ai-status");
  const aiResult = document.getElementById("ai-result");
  const aiFlagsList = document.getElementById("ai-flags-list");
  let previewUrl = null;
  let currentGmailTabId = null;

  imageInput.addEventListener("change", () => {
    const [file] = imageInput.files;
    if (!file) {
      return;
    }

    if (previewUrl) {
      URL.revokeObjectURL(previewUrl);
    }
    previewUrl = URL.createObjectURL(file);
    screenshotPreview.src = previewUrl;
    screenshotPreview.style.display = "block";
    imageStatus.textContent = "Ready for review.";
    imageResult.style.display = "none";
  });

  scanImageButton.addEventListener("click", async () => {
    const [file] = imageInput.files;
    if (!file) {
      imageStatus.textContent = "Choose a PNG, JPEG, or WebP screenshot first.";
      return;
    }

    scanImageButton.disabled = true;
    imageStatus.textContent = "Looking at the screenshot on-device...";
    imageResult.style.display = "none";
    imageExtractedText.innerHTML = "";

    try {
      const analysis = await analyzeScreenshotWithLocalAI(file, (message) => {
        imageStatus.textContent = message;
      });

      const observations = Array.isArray(analysis.observations) ? analysis.observations : [];

      imageStatus.textContent = analysis.summary || "Review complete.";
      imageRisk.textContent = `Risk Level: ${(analysis.risk_level || "unknown").toUpperCase()}`;
      imageResult.className =
        analysis.risk_level === "high" ? "result-box high-risk" :
        analysis.risk_level === "medium" ? "result-box medium-risk" :
        "result-box";

      imageExtractedText.innerHTML = "";
      if (observations.length) {
        const list = document.createElement("ul");
        list.style.margin = "0";
        list.style.paddingLeft = "18px";
        observations.forEach((item) => {
          const li = document.createElement("li");
          li.textContent = `${item.observation} — ${item.reason}`;
          list.appendChild(li);
        });
        imageExtractedText.appendChild(list);
      } else {
        imageExtractedText.textContent = "Nothing specific was flagged.";
      }

      imageResult.style.display = "block";
    } catch (error) {
      console.warn("Screenshot AI review failed", error);
      imageStatus.textContent = error.message || "Something went wrong reviewing that screenshot. Please try again.";
    } finally {
      scanImageButton.disabled = false;
    }
  });

  const loadEmail = () => {
    statusElement.textContent = "Checking Gmail...";
    resultBox.style.display = "none";
    riskElement.textContent = "";

    const queryTabs = (queryOptions, callback) => {
      chrome.tabs.query(queryOptions, (tabs) => {
        if (chrome.runtime.lastError) {
          callback(null, chrome.runtime.lastError.message);
          return;
        }
        callback(tabs, null);
      });
    };

    const findGmailTab = (callback) => {
      queryTabs({ active: true, currentWindow: true }, (tabs, error) => {
        if (error) {
          callback(null, error);
          return;
        }
        let tab = tabs && tabs[0];
        if (tab && tab.url && tab.url.includes("mail.google.com")) {
          callback(tab);
          return;
        }

        queryTabs({ active: true, lastFocusedWindow: true }, (tabs2, error2) => {
          if (error2) {
            callback(null, error2);
            return;
          }
          tab = tabs2 && tabs2[0];
          if (tab && tab.url && tab.url.includes("mail.google.com")) {
            callback(tab);
            return;
          }

          queryTabs({ url: "*://mail.google.com/*" }, (tabs3, error3) => {
            if (error3) {
              callback(null, error3);
              return;
            }
            callback(tabs3 && tabs3[0]);
          });
        });
      });
    };

    findGmailTab((tab, selectError) => {
      if (selectError) {
        statusElement.textContent = `Tab query failed: ${selectError}`;
        return;
      }

      if (!tab || !tab.id) {
        statusElement.textContent = "No active tab found";
        return;
      }

      if (tab.url && !tab.url.includes("mail.google.com")) {
        statusElement.textContent = "Open Gmail to scan emails";
        return;
      }

      currentGmailTabId = tab.id;

      const injectScanner = (done) => {
        chrome.scripting.executeScript(
          {
            target: { tabId: tab.id },
            files: ["model.js", "content.js"],
          },
          () => {
            if (chrome.runtime.lastError) {
              statusElement.textContent = "Unable to start the Gmail scanner";
              return;
            }
            setTimeout(done, 150);
          }
        );
      };

      const trySend = (attempt, hasInjected = false) => {
        chrome.tabs.sendMessage(
          tab.id,
          { action: "getEmail" },
          (response) => {
            if (chrome.runtime.lastError) {
              if (!hasInjected) {
                injectScanner(() => trySend(attempt, true));
              } else if (attempt < 5) {
                setTimeout(() => trySend(attempt + 1, true), 300);
              } else {
                statusElement.textContent = "Gmail is still loading—try again in a moment";
              }
              return;
            }

            if (response) {
              emailElement.textContent = response;
              statusElement.textContent = "Email detected from Gmail";
              resultBox.style.display = "block";

              chrome.tabs.sendMessage(
                tab.id,
                { action: "getRiskScore" },
                (riskResponse) => {
                  if (chrome.runtime.lastError) {
                    riskElement.textContent = "Risk score unavailable";
                    return;
                  }

                  if (riskResponse && riskResponse.risk !== undefined) {
                    const risk = riskResponse.risk;
                    riskElement.textContent = `Risk Level: ${riskResponse.label} (${(risk * 100).toFixed(0)}%)`;

                    if (risk >= 0.75) {
                      resultBox.className = "result-box high-risk";
                    } else if (risk >= 0.45) {
                      resultBox.className = "result-box medium-risk";
                    } else {
                      resultBox.className = "result-box";
                    }
                  } else {
                    riskElement.textContent = "Risk score unavailable";
                  }
                }
              );
            } else {
              statusElement.textContent = "Open an email to check it — nothing selected right now";
            }
          }
        );
      };

      trySend(1);
    });
  };

  // --- On-device AI for "Explain with AI" ---
  // Uses Chrome's built-in Prompt API (Gemini Nano), which runs entirely on
  // the user's machine — Chrome's own docs state no data is sent to Google
  // or any third party when using the model. This can only run in a window
  // context (popup/options page), not in the background service worker —
  // the Prompt API is explicitly unavailable in Web Workers.
  const AI_TEXT_RESPONSE_SCHEMA = {
    type: "object",
    properties: {
      summary: { type: "string" },
      risk_level: { type: "string", enum: ["low", "medium", "high"] },
      flags: {
        type: "array",
        items: {
          type: "object",
          properties: {
            phrase: { type: "string" },
            reason: { type: "string" },
            severity: { type: "string", enum: ["low", "medium", "high"] }
          },
          required: ["phrase", "reason", "severity"]
        }
      }
    },
    required: ["summary", "risk_level", "flags"]
  };

  const AI_TEXT_SYSTEM_PROMPT = "You are a careful assistant helping a non-technical person, possibly a senior citizen, figure out whether an email might be a phishing or scam attempt. You will be given the plain text of an email. Point out specific phrases, requests, or links that are red flags, and explain each one in one simple sentence. If nothing looks suspicious, say so and return an empty flags array. Every \"phrase\" value must be an exact, verbatim substring of the email text you were given — never rephrase it — since it will be searched for and highlighted in the original text.";

  // Screenshots don't have a DOM to highlight exact phrases against, so
  // this schema describes what's visible in the image instead of quoting
  // verbatim text (unlike the email schema above).
  const AI_IMAGE_RESPONSE_SCHEMA = {
    type: "object",
    properties: {
      summary: { type: "string" },
      risk_level: { type: "string", enum: ["low", "medium", "high"] },
      observations: {
        type: "array",
        items: {
          type: "object",
          properties: {
            observation: { type: "string" },
            reason: { type: "string" },
            severity: { type: "string", enum: ["low", "medium", "high"] }
          },
          required: ["observation", "reason", "severity"]
        }
      }
    },
    required: ["summary", "risk_level", "observations"]
  };

  const AI_IMAGE_SYSTEM_PROMPT = "You are a careful assistant helping a non-technical person, possibly a senior citizen, figure out whether a screenshot of an email or message might be a phishing or scam attempt. Look closely at the image: read any visible text, check the sender name and address if shown, look at any links or buttons, and note requests for passwords, payment, or personal information. Point out specific things you see that are red flags, and explain each one in one simple sentence. If nothing looks suspicious, say so and return an empty observations array.";

  async function createLocalAISession({ expectedInputs, systemPrompt, onProgress }) {
    if (typeof LanguageModel === "undefined") {
      throw new Error("This Chrome doesn't support on-device AI yet. It needs Chrome 138+ on Windows, macOS, or Linux — see chrome://on-device-internals for details.");
    }

    const availability = await LanguageModel.availability({ expectedInputs });
    if (availability === "unavailable") {
      throw new Error("On-device AI isn't available on this computer (needs a compatible OS/hardware — Windows, macOS, or Linux with a few GB of free space).");
    }

    if (availability !== "available") {
      onProgress?.("Downloading the on-device AI model — this only happens once and needs an unmetered connection...");
    }

    const createSession = () =>
      LanguageModel.create({
        expectedInputs,
        initialPrompts: [{ role: "system", content: systemPrompt }],
        monitor(m) {
          m.addEventListener("downloadprogress", (e) => {
            onProgress?.(`Downloading the on-device AI model — ${Math.round(e.loaded * 100)}% (first time only)`);
          });
        }
      });

    try {
      return await createSession();
    } catch (firstError) {
      // Known Chrome quirk: availability() can report "available" while
      // create() still fails — often because the model process crashed
      // repeatedly and Chrome stopped retrying, or a download is stuck
      // partway. A second attempt sometimes succeeds; if not, surface
      // concrete next steps rather than the raw browser error.
      onProgress?.("First attempt failed — trying once more...");
      try {
        return await createSession();
      } catch (secondError) {
        const rawMessage = secondError.message || String(secondError);
        if (/crashed too many times/i.test(rawMessage)) {
          throw new Error(
            "Chrome's on-device AI model has crashed too many times and Chrome has stopped trying to start it. " +
            "A restart alone usually only buys a few more attempts before this comes back — two things actually fix it: " +
            "(1) go to chrome://components, find \"Optimization Guide On Device Model,\" and click \"Check for update\" to " +
            "re-download it in case the current copy is stale or corrupted; (2) go to chrome://settings/help to make sure " +
            "Chrome itself is fully up to date, since this exact bug has been fixed in some Chrome releases. " +
            "Restart Chrome fully after either step."
          );
        }
        throw new Error(
          "Chrome's on-device AI model couldn't start, even though it reported itself as available. " +
          "This is a known Chrome issue, usually because the model process crashed or the download is stuck. " +
          "Try: open chrome://on-device-internals and check the \"Model status\" tab for a crash count or stuck download; " +
          "fully restart Chrome; make sure Chrome is up to date; and confirm there's still several GB of free disk space. " +
          `(Browser error: ${rawMessage})`
        );
      }
    }
  }

  async function explainWithLocalAI(text, onProgress) {
    const session = await createLocalAISession({
      expectedInputs: [{ type: "text" }],
      systemPrompt: AI_TEXT_SYSTEM_PROMPT,
      onProgress
    });

    try {
      onProgress?.("Reviewing the email on-device...");
      // Keep the request modest — Gemini Nano's context window is much
      // smaller than a cloud model's.
      const trimmedText = text.slice(0, 4000);
      const raw = await session.prompt(trimmedText, { responseConstraint: AI_TEXT_RESPONSE_SCHEMA });
      return JSON.parse(raw);
    } finally {
      session.destroy();
    }
  }

  async function analyzeScreenshotWithLocalAI(imageFile, onProgress) {
    // Chrome's Prompt API accepts an image directly (Blob/File included) —
    // no separate OCR step needed. The model reads the screenshot itself.
    const session = await createLocalAISession({
      expectedInputs: [{ type: "text" }, { type: "image" }],
      systemPrompt: AI_IMAGE_SYSTEM_PROMPT,
      onProgress
    });

    try {
      onProgress?.("Looking at the screenshot on-device...");
      console.log("[Gmail Helper] Sending image to on-device model:", {
        name: imageFile.name,
        type: imageFile.type,
        sizeBytes: imageFile.size
      });
      const raw = await session.prompt(
        [
          {
            role: "user",
            content: [
              { type: "text", value: "Look at this screenshot and assess whether it looks like a phishing or scam attempt." },
              { type: "image", value: imageFile }
            ]
          }
        ],
        { responseConstraint: AI_IMAGE_RESPONSE_SCHEMA }
      );
      console.log("[Gmail Helper] Raw model output:", raw);
      return JSON.parse(raw);
    } finally {
      session.destroy();
    }
  }
  // --- end on-device AI helper ---

  aiExplainButton.addEventListener("click", () => {
    if (!currentGmailTabId) {
      aiStatus.textContent = "Open an email in Gmail first.";
      return;
    }

    aiExplainButton.disabled = true;
    aiStatus.textContent = "Reading the email...";
    aiResult.style.display = "none";
    aiFlagsList.innerHTML = "";

    chrome.tabs.sendMessage(currentGmailTabId, { action: "getEmailBodyTextForAI" }, async (bodyResponse) => {
      if (chrome.runtime.lastError || !bodyResponse?.text) {
        aiStatus.textContent = "Open an email first — nothing to analyze right now.";
        aiExplainButton.disabled = false;
        return;
      }

      try {
        const analysis = await explainWithLocalAI(bodyResponse.text, (message) => {
          aiStatus.textContent = message;
        });

        const flags = Array.isArray(analysis.flags) ? analysis.flags : [];

        aiStatus.textContent = analysis.summary || "AI review complete.";
        aiResult.className =
          analysis.risk_level === "high" ? "result-box high-risk" :
          analysis.risk_level === "medium" ? "result-box medium-risk" :
          "result-box";
        aiResult.style.display = "block";

        if (flags.length) {
          flags.forEach((flag) => {
            const li = document.createElement("li");
            li.textContent = `"${flag.phrase}" — ${flag.reason}`;
            aiFlagsList.appendChild(li);
          });
        } else {
          const li = document.createElement("li");
          li.textContent = "Nothing specific was flagged.";
          aiFlagsList.appendChild(li);
        }

        // Highlight the flagged phrases directly in the Gmail message too.
        chrome.tabs.sendMessage(currentGmailTabId, { action: "applyAiHighlights", flags });
      } catch (error) {
        console.warn("On-device AI review failed", error);
        aiStatus.textContent = error.message || "AI review failed. Please try again.";
      } finally {
        aiExplainButton.disabled = false;
      }
    });
  });

  refreshButton.addEventListener("click", loadEmail);
  loadEmail();
});