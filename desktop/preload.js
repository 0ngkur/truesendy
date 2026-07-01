// Secure preload — exposes ONLY safe, named calls to the renderer via contextBridge.
// The renderer (web page) has NO direct Node access; everything native goes through here.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('ts', {
    pickEmailFile: () => ipcRenderer.invoke('pick-email-file'),
    saveExport: (defaultName, content) => ipcRenderer.invoke('save-export', defaultName, content),
    openExternal: (url) => ipcRenderer.invoke('open-external', url),
    configGet: () => ipcRenderer.invoke('config-get'),
    configSet: (cfg) => ipcRenderer.invoke('config-set', cfg),
    appVersion: () => ipcRenderer.invoke('app-version'),
});
