chrome.action.onClicked.addListener(() => {
  chrome.runtime.sendNativeMessage(
    "com.nativebridgeguard.lab",
    {type: "ping", source: "lab-extension"},
    (response) => {
      if (chrome.runtime.lastError) {
        console.error(chrome.runtime.lastError.message);
        return;
      }
      console.log("NativeBridgeGuard lab response:", response);
    }
  );
});
