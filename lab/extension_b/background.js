// NBG Lab Extension B — harmless lab helper.
// Its ONLY behaviour is to send a ping to the lab native host and log the pong.
chrome.action.onClicked.addListener(() => {
  chrome.runtime.sendNativeMessage(
    "com.nativebridgeguard.lab",
    {type: "ping", source: "lab-extension-b"},
    (response) => {
      if (chrome.runtime.lastError) {
        console.error(chrome.runtime.lastError.message);
        return;
      }
      console.log("NativeBridgeGuard lab response (B):", response);
    }
  );
});
