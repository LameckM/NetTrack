const { contextBridge } = require("electron");

contextBridge.exposeInMainWorld("nettrack", {
  platform: process.platform,
  desktop: true
});
