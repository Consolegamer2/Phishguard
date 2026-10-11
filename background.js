chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete" || !tab.url || !tab.url.includes("mail.google.com")) {
    return;
  }

  chrome.tabs.sendMessage(tabId, { action: "getEmail" }, (response) => {
    if (chrome.runtime.lastError) {
      console.warn("Background: could not message content script", chrome.runtime.lastError.message);
      return;
    }
    if (!response) {
      return;
    }

    chrome.storage.local.set({ lastEmail: response }, () => {
      if (chrome.runtime.lastError) {
        console.warn("Background: could not save lastEmail", chrome.runtime.lastError.message);
      } else {
        console.log("Email grabbed:", response);
      }
    });
  });
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "getStoredEmail") {
    chrome.storage.local.get(["lastEmail"], (data) => {
      if (chrome.runtime.lastError) {
        sendResponse({ error: chrome.runtime.lastError.message });
        return;
      }
      sendResponse({ lastEmail: data.lastEmail || null });
    });
    return true;
  }
});