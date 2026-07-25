const state = {
  ws: null,
  localStream: null,
  localTrack: null,
  audioCtx: null,
  masterOutput: null,
  radioStaticBuffer: null,
  radioStaticLoading: false,
  radioStaticSource: null,
  radioStaticGain: null,
  radioNoiseGain: null,
  radioNoiseCrackleGain: null,
  radioNoiseFlutterDepth: null,
  blockingToneGain: null,
  selfId: null,
  selfName: "",
  selfRole: "operator",
  rank: "t1",
  isAdmin: false,
  isMod: false,
  isT1: true,
  currentRoom: null,
  currentRoomName: "",
  currentCreatorId: null,
  peers: new Map(),
  currentHolderId: null,
  currentQueue: [],
  activeSpeakerId: null,
  activeChannel: null,
  selectedChannel: null,
  availableChannels: [],
  lastRxActive: false,
  lastEotAt: 0,
  lastRogerAt: 0,
  rogerBeepBuffer: null,
  rogerBeepLoading: false,
  txGranted: false,
  isPttPressed: false,
  powerMode: "off",
  micAnalyserNode: null,
  micAnalyserSourceNode: null,
  micVisualizerAnimationId: null,
  cleanMonitorEnabled: false,
  serverProbeTimerId: null,
  serverProbeInFlight: false,
  selectedMicDeviceId: "",
  selectedOutputDeviceId: "",
  pttKeyCode: "Space",
  masterVolume: 1,
  rxVolume: 1,
  menuState: {
    selectedItem: 0, // 0:channel 1:role 2:trainId 3:mic 4:output 5:ptt
    editMode: false,
    trainIdEditValue: "",
    channelEditValue: null
  }
};

const stunConfig = {
  iceServers: [{ urls: "stun:stun.l.google.com:19302" }]
};

const DEFAULT_CHANNEL = "operators";
const CHANNEL_LABELS = {
  "operators": "Operators",
  "a1-irt": "A1-IRT",
  "b1-bmt": "B1-BMT",
  "b2-ind": "B2-IND",
  "y-yard": "Y-Yard"
};

const SETTINGS_STORAGE_KEY = "openbve-radio-settings-v1";

// Auth state populated from server after login
let currentUserId = null;
let currentUsername = null;

function withAuthQuery(path) {
  return path; // auth is cookie-based; no query param needed
}

async function ensureAuthenticated() {
  try {
    const res = await fetch("/auth/status", { method: "GET", cache: "no-store" });
    if (!res.ok) return false;
    const data = await res.json().catch(() => null);
    if (data && data.authenticated) {
      currentUserId = data.userId || null;
      currentUsername = data.username || null;
      return true;
    }
    // Not logged in — redirect to login page
    window.location.href = "/login";
    return false;
  } catch (_err) {
    window.location.href = "/login";
    return false;
  }
}

const roleEl = document.getElementById("role");
const trainIdEl = document.getElementById("trainId");
const joinBtn = document.getElementById("joinBtn");
const adminPageBtn = document.getElementById("adminPageBtn");
const leaveServerBtn = document.getElementById("leaveServerBtn");
const pttBtn = document.getElementById("pttBtn");
const cleanCheckBtn = document.getElementById("cleanCheckBtn");
const radioFrameEl = document.getElementById("radioFrame");
const volKnobEl = document.querySelector(".apx-vol");
const serverStatusEl = document.getElementById("serverStatus");
const userStatusEl = document.getElementById("userStatus");
const statusEl = document.getElementById("status");
const channelStateEl = document.getElementById("channelState");
const menuChannelEl = document.getElementById("menuChannel");
const menuChannelArrowsEl = document.getElementById("menuChannelArrows");
const menuRoleEl = document.getElementById("menuRole");
const menuRoleArrowsEl = document.getElementById("menuRoleArrows");
const menuTrainIdEl = document.getElementById("menuTrainId");
const menuMicEl = document.getElementById("menuMic");
const menuMicArrowsEl = document.getElementById("menuMicArrows");
const menuOutputEl = document.getElementById("menuOutput");
const menuOutputArrowsEl = document.getElementById("menuOutputArrows");
const menuPttEl = document.getElementById("menuPtt");
const rxValueEl = document.getElementById("rxValue");
const volumeValueEl = document.getElementById("volumeValue");
const serverNameEl = document.getElementById("serverName");
const txLightEl = document.getElementById("txLight");
const peersEl = document.getElementById("peers");
const opsTabBtnEl = document.getElementById("opsTabBtn");
const serverAdminTabBtnEl = document.getElementById("serverAdminTabBtn");
const adminTabBtnEl = null; // admin is now a sidebar, not a tab
const settingsTabBtnEl = document.getElementById("settingsTabBtn");
const opsPanelEl = document.getElementById("opsPanel");
const adminPanelEl = null; // admin is now a sidebar, not a tab
const settingsPanelEl = document.getElementById("settingsPanel");
const adminSidebarEl = document.getElementById("adminSidebar");
const memberSidebarEl = document.getElementById("memberSidebar");
const micSelectEl = document.getElementById("micSelect");
const outputSelectEl = document.getElementById("outputSelect");
const pttKeyCaptureEl = document.getElementById("pttKeyCapture");

// Room management elements
const roomSelectionModalEl = document.getElementById("roomSelectionModal");
const joinRoomTabEl = document.getElementById("joinRoomTab");
const createRoomTabEl = document.getElementById("createRoomTab");
const roomListEl = document.getElementById("roomList");
const createRoomFormEl = document.getElementById("createRoomForm");
const newRoomNameEl = document.getElementById("newRoomName");
const newRoomPasswordEl = document.getElementById("newRoomPassword");
const newRoomUserNameEl = document.getElementById("newRoomUserName");
const createRoomErrorEl = document.getElementById("createRoomError");
const adminMembersListEl = document.getElementById("adminMembersList");
const adminRosterListEl = document.getElementById("adminRosterList"); // kept for compat (null now)
const rosterBtnWrapEl = document.getElementById("rosterBtnWrap");
const openRosterBtnEl = document.getElementById("openRosterBtn");
const rosterModalEl = document.getElementById("rosterModal");
const closeRosterBtnEl = document.getElementById("closeRosterBtn");
const rosterModalListEl = document.getElementById("rosterModalList");
const openServerEditorBtnEl = document.getElementById("openServerEditorBtn");
const serverEditorModalEl = document.getElementById("serverEditorModal");
const closeServerEditorBtnEl = document.getElementById("closeServerEditorBtn");
const serverEditorListEl = document.getElementById("serverEditorList");
const adminNewPasswordEl = document.getElementById("adminNewPassword");
const adminChangePasswordBtnEl = document.getElementById("adminChangePasswordBtn");

// ── Rank system ──────────────────────────────────────────
// Ranks: index 0 = highest
const RANK_HIERARCHY = ["admin", "mod", "t3", "t2", "t1"];
const RANK_LABELS    = { admin: "Admin", mod: "Moderator", t3: "T3", t2: "T2", t1: "T1" };

// Session roles: index 0 = highest
const SESSION_HIERARCHY = ["dispatcher", "operator", "listener"];
const SESSION_LABELS    = { dispatcher: "Dispatcher", operator: "Operator", listener: "Listener" };

// Session roles each rank may choose from
function allowedSessionRoles(rank) {
  if (rank === "t1")                 return ["listener"];
  if (rank === "t2")                 return ["listener", "operator"];
  return ["listener", "operator", "dispatcher"]; // t3, mod, admin
}

// Populate the session role <select> with options the user is allowed to pick.
function populateRoleSelect(rank, selectedRole) {
  if (!roleEl) return;
  const roleRow = roleEl.closest(".apx-lbl") || roleEl.parentElement;
  if (roleRow) roleRow.hidden = false; // Always show the dropdown

  const allowed = allowedSessionRoles(rank);
  roleEl.innerHTML = "";
  for (const r of SESSION_HIERARCHY) {
    if (!allowed.includes(r)) continue;
    const opt = document.createElement("option");
    opt.value = r;
    opt.textContent = SESSION_LABELS[r] || r;
    if (r === selectedRole) opt.selected = true;
    roleEl.appendChild(opt);
  }
}

function syncRoleSettingOnRadio() {
  populateRoleSelect(state.rank, state.selfRole);
}

function showTab(tabBtn, tabPanel) {
  // Hide all tabs
  if (opsTabBtnEl) {
    opsTabBtnEl.classList.remove("active");
    opsTabBtnEl.setAttribute("aria-selected", "false");
  }
  if (settingsTabBtnEl) {
    settingsTabBtnEl.classList.remove("active");
    settingsTabBtnEl.setAttribute("aria-selected", "false");
  }
  if (opsPanelEl) opsPanelEl.classList.remove("active");
  if (settingsPanelEl) settingsPanelEl.classList.remove("active");
  if (opsPanelEl) opsPanelEl.hidden = true;
  if (settingsPanelEl) settingsPanelEl.hidden = true;

  // Show selected tab
  if (tabBtn) {
    tabBtn.classList.add("active");
    tabBtn.setAttribute("aria-selected", "true");
  }
  if (tabPanel) {
    tabPanel.classList.add("active");
    tabPanel.hidden = false;
  }
}

function setPowerState(mode) {
  if (!radioFrameEl) {
    return;
  }

  state.powerMode = mode;
  radioFrameEl.classList.remove("power-off", "power-connecting", "power-on");
  radioFrameEl.classList.add(`power-${mode}`);

  // Show room selection modal when disconnected
  if (mode === "off") {
    if (roomSelectionModalEl) {
      roomSelectionModalEl.classList.add('active');
      showRoomTab('join-room');
    }
  } else if (mode === "on") {
    if (roomSelectionModalEl) roomSelectionModalEl.classList.remove('active');
    showTab(opsTabBtnEl, opsPanelEl);
  }

  if (joinBtn) {
    if (mode === "on") {
      joinBtn.textContent = "Disconnect";
    } else if (mode === "connecting") {
      joinBtn.textContent = "Connecting...";
    } else {
      joinBtn.textContent = "Connect";
    }
  }
}

function updateCleanCheckButton() {
  if (!cleanCheckBtn) {
    return;
  }

  cleanCheckBtn.textContent = state.cleanMonitorEnabled ? "Audio Filter: Off" : "Audio Filter: On";
  cleanCheckBtn.classList.toggle("active", state.cleanMonitorEnabled);
}

function routePeerAudio(peer, isActiveSpeaker) {
  if (!peer || !peer.audio) {
    return;
  }

  // Relay peers have no MediaStream behind peer.audio, so their unprocessed
  // monitoring path is a WebAudio tap rather than the <audio> element.
  const setCleanGain = (value) => {
    if (peer.relayCleanGain) {
      peer.relayCleanGain.gain.value = value;
    }
  };
  const isRelayPeer = peer.transport === "relay";

  // Half-duplex behavior: while transmitting, do not monitor inbound audio.
  if (state.isPttPressed) {
    peer.audio.muted = true;
    peer.audio.volume = 0;
    if (peer.peerGainNode) {
      peer.peerGainNode.gain.value = 0;
    }
    setCleanGain(0);
    return;
  }

  if (!isActiveSpeaker) {
    peer.audio.muted = true;
    peer.audio.volume = 0;
    if (peer.peerGainNode) {
      peer.peerGainNode.gain.value = 0;
    }
    setCleanGain(0);
    return;
  }

  if (state.cleanMonitorEnabled) {
    peer.audio.muted = false;
    peer.audio.volume = state.rxVolume;
    if (peer.peerGainNode) {
      peer.peerGainNode.gain.value = 0;
    }
    setCleanGain(isRelayPeer ? state.rxVolume : 0);
    return;
  }

  peer.audio.muted = true;
  peer.audio.volume = 0;
  if (peer.peerGainNode) {
    peer.peerGainNode.gain.value = state.rxVolume;
  }
  setCleanGain(0);
}

function applyCurrentMonitorRouting() {
  for (const [peerId, peer] of state.peers.entries()) {
    const isActiveSpeaker = Boolean(state.activeSpeakerId && peerId === state.activeSpeakerId);
    routePeerAudio(peer, isActiveSpeaker);
  }
}

function setServerStatus(message) {
  serverStatusEl.textContent = message;
}

function saveSettings() {
  try {
    localStorage.setItem(
      SETTINGS_STORAGE_KEY,
      JSON.stringify({
        mic: state.selectedMicDeviceId || "",
        output: state.selectedOutputDeviceId || "",
        pttKey: state.pttKeyCode || "Space",
        masterVol: state.masterVolume,
        rxVol: state.rxVolume
      })
    );
  } catch (_err) {
    // Ignore storage failures in private/restricted contexts.
  }
}

function loadSettings() {
  try {
    const raw = localStorage.getItem(SETTINGS_STORAGE_KEY);
    if (!raw) {
      return;
    }

    const saved = JSON.parse(raw);
    if (!saved || typeof saved !== "object") {
      return;
    }

    state.selectedMicDeviceId = typeof saved.mic === "string" ? saved.mic : "";
    state.selectedOutputDeviceId = typeof saved.output === "string" ? saved.output : "";
    state.pttKeyCode = typeof saved.pttKey === "string" ? saved.pttKey : "Space";
    state.masterVolume = Number.isFinite(saved.masterVol) ? Math.max(0, Math.min(1, saved.masterVol)) : 1;
    state.rxVolume = Number.isFinite(saved.rxVol) ? Math.max(0, Math.min(1, saved.rxVol)) : 1;
  } catch (_err) {
    // Ignore malformed setting payloads.
  }
}

async function probeServerStatus() {
  if (state.serverProbeInFlight) {
    return;
  }

  if (state.ws && state.ws.readyState === WebSocket.OPEN) {
    setServerStatus("Server: online (connected)");
    return;
  }

  state.serverProbeInFlight = true;
  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort(), 2500);

  try {
    const response = await fetch(withAuthQuery("/api/rooms"), {
      method: "GET",
      cache: "no-store",
      signal: controller.signal
    });

    if (response.ok) {
      setServerStatus("Server: online");
    } else if (response.status === 401) {
      setServerStatus("Server: auth required");
    } else {
      setServerStatus("Server: offline");
    }
  } catch (_err) {
    setServerStatus("Server: offline");
  } finally {
    window.clearTimeout(timeoutId);
    state.serverProbeInFlight = false;
  }
}

function startServerStatusProbe() {
  if (state.serverProbeTimerId) {
    window.clearInterval(state.serverProbeTimerId);
  }

  probeServerStatus();
  state.serverProbeTimerId = window.setInterval(() => {
    probeServerStatus();
  }, 8000);
}

function setUserStatus(message) {
  userStatusEl.textContent = message;
}

function setActiveTab(tabName) {
  // Settings tab has been removed; only "ops" tab exists now
  if (!opsTabBtnEl || !opsPanelEl) return;
  opsTabBtnEl.classList.add("active");
  opsPanelEl.classList.add("active");
  opsTabBtnEl.setAttribute("aria-selected", "true");
  if (settingsTabBtnEl) settingsTabBtnEl.classList.remove("active");
  if (settingsPanelEl) settingsPanelEl.classList.remove("active");
}

async function applyAudioOutputSink(audioElement) {
  if (!audioElement) {
    return;
  }

  if (typeof audioElement.setSinkId !== "function") {
    return;
  }

  try {
    await audioElement.setSinkId(state.selectedOutputDeviceId || "");
  } catch (_err) {
    setStatus("Output device switch blocked by browser/device policy");
  }
}

async function applyAudioContextOutputSink() {
  if (!state.audioCtx || typeof state.audioCtx.setSinkId !== "function") {
    return false;
  }

  try {
    await state.audioCtx.setSinkId(state.selectedOutputDeviceId || "default");
    return true;
  } catch (_err) {
    return false;
  }
}

async function applyOutputDeviceToPeers() {
  const contextSinkApplied = await applyAudioContextOutputSink();

  for (const peer of state.peers.values()) {
    await applyAudioOutputSink(peer.audio);
  }

  if (!contextSinkApplied && state.audioCtx) {
    setStatus("Output switch may be limited by your browser for radio FX audio");
  }
}

async function populateDeviceSelectors() {
  if (!navigator.mediaDevices || typeof navigator.mediaDevices.enumerateDevices !== "function") {
    return;
  }

  try {
    const devices = await navigator.mediaDevices.enumerateDevices();

    if (micSelectEl) {
      const selected = state.selectedMicDeviceId;
      micSelectEl.innerHTML = '<option value="">Default microphone</option>';
      let micIndex = 1;
      for (const device of devices) {
        if (device.kind !== "audioinput") {
          continue;
        }
        const option = document.createElement("option");
        option.value = device.deviceId;
        option.textContent = device.label || `Microphone ${micIndex}`;
        micSelectEl.appendChild(option);
        micIndex += 1;
      }
      micSelectEl.value = selected;
    }

    if (outputSelectEl) {
      const selected = state.selectedOutputDeviceId;
      outputSelectEl.innerHTML = '<option value="">Default output</option>';
      let outIndex = 1;
      for (const device of devices) {
        if (device.kind !== "audiooutput") {
          continue;
        }
        const option = document.createElement("option");
        option.value = device.deviceId;
        option.textContent = device.label || `Headset/Speaker ${outIndex}`;
        outputSelectEl.appendChild(option);
        outIndex += 1;
      }
      outputSelectEl.value = selected;
    }
  } catch (_err) {
    // Ignore enumeration errors when browser blocks device labels pre-permission.
  }
  // Refresh LCD menu device labels
  if (typeof updateMenuDisplay === "function") updateMenuDisplay();
}

async function switchMicrophone(deviceId) {
  state.selectedMicDeviceId = deviceId || "";
  saveSettings();

  if (!state.ws || state.ws.readyState !== WebSocket.OPEN) {
    return;
  }

  try {
    const rawStream = await getMicrophoneStream();
    const newStream = createBoostedMicrophoneStream(rawStream);
    const newTrack = newStream.getAudioTracks()[0];

    if (!newTrack) {
      return;
    }

    for (const peer of state.peers.values()) {
      if (!peer.pc) {
        continue;
      }
      const sender = peer.pc.getSenders().find((item) => item.track && item.track.kind === "audio");
      if (sender) {
        await sender.replaceTrack(newTrack);
      }
    }

    if (state.localStream) {
      for (const track of state.localStream.getTracks()) {
        track.stop();
      }
    }

    state.localStream = newStream;
    state.localTrack = newTrack;
    state.localTrack.enabled = state.txGranted;
    setStatus("Microphone updated");
  } catch (_err) {
    setStatus("Failed to switch microphone");
  }
}

function unlockRemoteAudio() {
  for (const peer of state.peers.values()) {
    if (!peer.audio || !peer.audio.srcObject) {
      continue;
    }

    peer.audio.play().catch(() => {
      // Some mobile browsers still require repeated user gestures.
    });
  }
}

function getParticipantStatus(userId) {
  if (state.currentHolderId === userId) {
    return "TX";
  }

  const queuePosition = state.currentQueue.indexOf(userId);
  if (queuePosition >= 0) {
    return `Q${queuePosition + 1}`;
  }

  return "RX";
}

function updateSelfStatus() {
  if (!state.ws || state.ws.readyState !== WebSocket.OPEN) {
    setUserStatus("User: offline");
    return;
  }

  if (!state.selfId) {
    setUserStatus("User: joining...");
    return;
  }

  if (state.txGranted) {
    setUserStatus("User: transmitting");
    return;
  }

  const queuePosition = state.currentQueue.indexOf(state.selfId);
  if (queuePosition >= 0) {
    setUserStatus(`User: queued (#${queuePosition + 1})`);
    return;
  }

  setUserStatus("User: listening");
}

function createLoopingNoiseBuffer(ctx, seconds = 2) {
  const frameCount = Math.max(1, Math.floor(ctx.sampleRate * seconds));
  const buffer = ctx.createBuffer(1, frameCount, ctx.sampleRate);
  const channel = buffer.getChannelData(0);

  for (let i = 0; i < frameCount; i += 1) {
    channel[i] = Math.random() * 2 - 1;
  }

  return buffer;
}

function createCrackleBuffer(ctx, seconds = 1.5) {
  const frameCount = Math.max(1, Math.floor(ctx.sampleRate * seconds));
  const buffer = ctx.createBuffer(1, frameCount, ctx.sampleRate);
  const channel = buffer.getChannelData(0);

  for (let i = 0; i < frameCount; i += 1) {
    channel[i] = 0;

    if (Math.random() < 0.0009) {
      const pulse = (Math.random() * 2 - 1) * 0.7;
      channel[i] = pulse;

      // Give each impulse a short decay tail to mimic bursty RF crackle.
      if (i + 1 < frameCount) {
        channel[i + 1] += pulse * 0.5;
      }
      if (i + 2 < frameCount) {
        channel[i + 2] += pulse * 0.25;
      }
    }
  }

  return buffer;
}

function createWalkieDistortionCurve(amount = 100) {
  const size = 44100;
  const curve = new Float32Array(size);

  for (let i = 0; i < size; i += 1) {
    const x = (i * 2) / size - 1;
    curve[i] = ((3 + amount) * x * 20 * (Math.PI / 180)) / (Math.PI + amount * Math.abs(x));
  }

  return curve;
}

// Hard tanh saturation — sounds like an overdriven RF stage
function createRadioSaturationCurve(drive = 260) {
  const size = 512;
  const curve = new Float32Array(size);
  const k = drive / 100;
  for (let i = 0; i < size; i++) {
    const x = (i * 2) / size - 1;
    curve[i] = Math.tanh(k * x) / Math.tanh(k); // normalised to ±1
  }
  return curve;
}

async function loadRogerBeepSample() {
  if (!state.audioCtx || state.rogerBeepBuffer || state.rogerBeepLoading) {
    return;
  }

  state.rogerBeepLoading = true;
  try {
    const response = await fetch(withAuthQuery("radiobeep.wav"), { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`Failed to load roger beep: HTTP ${response.status}`);
    }

    const arrayBuffer = await response.arrayBuffer();
    const decoded = await state.audioCtx.decodeAudioData(arrayBuffer.slice(0));
    state.rogerBeepBuffer = decoded;
  } catch (_err) {
    // Keep synthetic fallback when external beep file is unavailable.
  } finally {
    state.rogerBeepLoading = false;
  }
}

function ensureRadioStaticSource() {
  if (!state.audioCtx || !state.radioStaticBuffer || !state.radioStaticGain || state.radioStaticSource) {
    return;
  }

  const source = state.audioCtx.createBufferSource();
  source.buffer = state.radioStaticBuffer;
  source.loop = true;
  source.connect(state.radioStaticGain);
  source.start();
  source.onended = () => {
    if (state.radioStaticSource === source) {
      state.radioStaticSource = null;
    }
  };
  state.radioStaticSource = source;
}

async function loadRadioStaticSample() {
  if (!state.audioCtx || state.radioStaticBuffer || state.radioStaticLoading) {
    return;
  }

  state.radioStaticLoading = true;
  try {
    const response = await fetch(withAuthQuery("radiostatic.wav"), { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`Failed to load radio static: HTTP ${response.status}`);
    }

    const arrayBuffer = await response.arrayBuffer();
    const decoded = await state.audioCtx.decodeAudioData(arrayBuffer.slice(0));
    state.radioStaticBuffer = decoded;
    ensureRadioStaticSource();
    if (state.lastRxActive) {
      // If RX is already active, switch to sample static immediately.
      updateNoiseLevel(true);
    }
  } catch (_err) {
    // Keep synthetic static fallback when external sample is unavailable.
  } finally {
    state.radioStaticLoading = false;
  }
}

function initAudioEngine() {
  if (state.audioCtx) {
    if (state.audioCtx.state === "suspended") {
      state.audioCtx.resume().catch(() => {});
    }
    return;
  }

  const AudioCtx = window.AudioContext || window.webkitAudioContext;
  if (!AudioCtx) {
    return;
  }

  const ctx = new AudioCtx();
  const masterGain = ctx.createGain();
  masterGain.gain.value = 1.0;
  masterGain.connect(ctx.destination);

  const hissSource = ctx.createBufferSource();
  hissSource.buffer = createLoopingNoiseBuffer(ctx, 2.5);
  hissSource.loop = true;

  const crackleSource = ctx.createBufferSource();
  crackleSource.buffer = createCrackleBuffer(ctx, 1.6);
  crackleSource.loop = true;

  const noiseHighpass = ctx.createBiquadFilter();
  noiseHighpass.type = "highpass";
  noiseHighpass.frequency.value = 1750;

  const noiseLowpass = ctx.createBiquadFilter();
  noiseLowpass.type = "lowpass";
  noiseLowpass.frequency.value = 3900;

  const noisePresence = ctx.createBiquadFilter();
  noisePresence.type = "peaking";
  noisePresence.frequency.value = 2650;
  noisePresence.Q.value = 1.3;
  noisePresence.gain.value = 4.2;

  const crackleHighpass = ctx.createBiquadFilter();
  crackleHighpass.type = "highpass";
  crackleHighpass.frequency.value = 2500;

  const crackleLowpass = ctx.createBiquadFilter();
  crackleLowpass.type = "lowpass";
  crackleLowpass.frequency.value = 6200;

  const noiseGain = ctx.createGain();
  noiseGain.gain.value = 0;

  const crackleGain = ctx.createGain();
  crackleGain.gain.value = 0;

  const radioStaticGain = ctx.createGain();
  radioStaticGain.gain.value = 0;

  const blockingToneGain = ctx.createGain();
  blockingToneGain.gain.value = 0;

  const blockOscA = ctx.createOscillator();
  blockOscA.type = "sine";
  blockOscA.frequency.value = 910;

  const blockOscB = ctx.createOscillator();
  blockOscB.type = "square";
  blockOscB.frequency.value = 1280;

  const blockWobble = ctx.createOscillator();
  blockWobble.type = "triangle";
  blockWobble.frequency.value = 19;

  const blockWobbleDepth = ctx.createGain();
  blockWobbleDepth.gain.value = 10;

  const noiseFlutter = ctx.createOscillator();
  noiseFlutter.type = "triangle";
  noiseFlutter.frequency.value = 5.2;

  const noiseFlutterDepth = ctx.createGain();
  noiseFlutterDepth.gain.value = 0;

  hissSource.connect(noiseHighpass);
  noiseHighpass.connect(noiseLowpass);
  noiseLowpass.connect(noisePresence);
  noisePresence.connect(noiseGain);

  crackleSource.connect(crackleHighpass);
  crackleHighpass.connect(crackleLowpass);
  crackleLowpass.connect(crackleGain);

  noiseFlutter.connect(noiseFlutterDepth);
  noiseFlutterDepth.connect(noiseGain.gain);

  blockWobble.connect(blockWobbleDepth);
  blockWobbleDepth.connect(blockOscA.frequency);
  blockWobbleDepth.connect(blockOscB.frequency);

  blockOscA.connect(blockingToneGain);
  blockOscB.connect(blockingToneGain);

  noiseGain.connect(masterGain);
  crackleGain.connect(masterGain);
  radioStaticGain.connect(masterGain);
  blockingToneGain.connect(masterGain);

  hissSource.start();
  crackleSource.start();
  noiseFlutter.start();
  blockOscA.start();
  blockOscB.start();
  blockWobble.start();

  state.audioCtx = ctx;
  state.masterOutput = masterGain;
  state.radioStaticGain = radioStaticGain;
  state.radioNoiseGain = noiseGain;
  state.radioNoiseCrackleGain = crackleGain;
  state.radioNoiseFlutterDepth = noiseFlutterDepth;
  state.blockingToneGain = blockingToneGain;
  applyVolumeState();

  if (state.selectedOutputDeviceId) {
    applyAudioContextOutputSink();
  }

  loadRogerBeepSample().catch(() => {
    // Ignore lazy load failures and keep fallback tone.
  });
  loadRadioStaticSample().catch(() => {
    // Ignore lazy load failures and keep fallback static.
  });
}

function updateNoiseLevel(active) {
  if (!state.audioCtx || !state.radioNoiseGain || !state.radioNoiseCrackleGain || !state.radioNoiseFlutterDepth) {
    return;
  }

  const now = state.audioCtx.currentTime;
  state.radioNoiseGain.gain.cancelScheduledValues(now);
  state.radioNoiseCrackleGain.gain.cancelScheduledValues(now);
  state.radioNoiseFlutterDepth.gain.cancelScheduledValues(now);
  if (state.radioStaticGain) {
    state.radioStaticGain.gain.cancelScheduledValues(now);
  }

  const hasExternalStatic = Boolean(state.radioStaticBuffer && state.radioStaticGain);
  if (hasExternalStatic) {
    ensureRadioStaticSource();
  }

  if (!active) {
    if (state.radioStaticGain) {
      state.radioStaticGain.gain.setValueAtTime(0, now);
    }
    state.radioNoiseGain.gain.setValueAtTime(0, now);
    state.radioNoiseCrackleGain.gain.setValueAtTime(0, now);
    state.radioNoiseFlutterDepth.gain.setValueAtTime(0, now);
    return;
  }

  if (hasExternalStatic && state.radioStaticGain) {
    state.radioStaticGain.gain.setValueAtTime(0.11, now);
    state.radioNoiseGain.gain.setValueAtTime(0, now);
    state.radioNoiseCrackleGain.gain.setValueAtTime(0, now);
    state.radioNoiseFlutterDepth.gain.setValueAtTime(0, now);
    return;
  }

  state.radioNoiseGain.gain.setValueAtTime(0.0065, now);
  state.radioNoiseCrackleGain.gain.setValueAtTime(0.0055, now);
  state.radioNoiseFlutterDepth.gain.setValueAtTime(0.0008, now);
}

function cutNoiseNow() {
  if (!state.audioCtx || !state.radioNoiseGain) {
    return;
  }

  const now = state.audioCtx.currentTime;
  if (state.radioStaticGain) {
    state.radioStaticGain.gain.cancelScheduledValues(now);
    state.radioStaticGain.gain.setValueAtTime(0, now);
  }
  state.radioNoiseGain.gain.cancelScheduledValues(now);
  state.radioNoiseGain.gain.setValueAtTime(0, now);

  if (state.radioNoiseCrackleGain) {
    state.radioNoiseCrackleGain.gain.cancelScheduledValues(now);
    state.radioNoiseCrackleGain.gain.setValueAtTime(0, now);
  }

  if (state.radioNoiseFlutterDepth) {
    state.radioNoiseFlutterDepth.gain.cancelScheduledValues(now);
    state.radioNoiseFlutterDepth.gain.setValueAtTime(0, now);
  }
}

// Squelch open: short decaying noise burst (the gate-open "pop") when RX begins
function playSquelchOpen() {
  if (!state.audioCtx || !state.masterOutput) return;
  const ctx = state.audioCtx;
  const out = state.masterOutput;
  const now = ctx.currentTime;

  const sampleCount = Math.floor(ctx.sampleRate * 0.014);
  const buf = ctx.createBuffer(1, sampleCount, ctx.sampleRate);
  const ch = buf.getChannelData(0);
  for (let i = 0; i < sampleCount; i++) {
    ch[i] = (Math.random() * 2 - 1) * Math.exp(-i / (sampleCount * 0.28));
  }

  const src = ctx.createBufferSource();
  src.buffer = buf;

  const bp = ctx.createBiquadFilter();
  bp.type = "bandpass";
  bp.frequency.value = 1900;
  bp.Q.value = 0.55;

  const g = ctx.createGain();
  g.gain.setValueAtTime(0.32, now);
  g.gain.linearRampToValueAtTime(0, now + 0.014);

  src.connect(bp);
  bp.connect(g);
  g.connect(out);
  src.start(now);
}

// Squelch close: noise burst then sharp cut — classic squelch tail
function playSquelchClose() {
  if (!state.audioCtx) return;
  const ctx = state.audioCtx;
  const now = ctx.currentTime;
  const sg = state.radioStaticGain;
  const ng = state.radioNoiseGain;
  const cg = state.radioNoiseCrackleGain;
  const fd = state.radioNoiseFlutterDepth;

  if (sg) sg.gain.cancelScheduledValues(now);
  ng.gain.cancelScheduledValues(now);
  if (cg) cg.gain.cancelScheduledValues(now);
  if (fd) fd.gain.cancelScheduledValues(now);

  // Instant burst
  if (sg) sg.gain.setValueAtTime(0.19, now);
  ng.gain.setValueAtTime(0.12, now);
  if (cg) cg.gain.setValueAtTime(0.09, now);
  if (fd) fd.gain.setValueAtTime(0, now);

  // Hold ~75 ms then cut sharply over 12 ms
  const holdEnd = now + 0.075;
  if (sg) {
    sg.gain.setValueAtTime(0.19, holdEnd);
    sg.gain.linearRampToValueAtTime(0, holdEnd + 0.012);
  }
  ng.gain.setValueAtTime(0.12, holdEnd);
  ng.gain.linearRampToValueAtTime(0, holdEnd + 0.012);
  if (cg) {
    cg.gain.setValueAtTime(0.09, holdEnd);
    cg.gain.linearRampToValueAtTime(0, holdEnd + 0.012);
  }
}

function shouldPlayBlockingTone() {
  const hasContention = Boolean(state.currentHolderId) && state.currentQueue.length > 0;
  const hasActiveRx = Boolean(state.activeSpeakerId);
  const selfIsHolder = Boolean(state.selfId) && state.selfId === state.currentHolderId;
  const selfIsQueued = Boolean(state.selfId) && state.currentQueue.includes(state.selfId);
  const selfIsTransmitting = state.txGranted || state.isPttPressed;
  return hasContention && hasActiveRx && !selfIsHolder && !selfIsQueued && !selfIsTransmitting;
}

function syncBlockingTone() {
  if (!state.audioCtx || !state.blockingToneGain) {
    return;
  }

  const now = state.audioCtx.currentTime;
  const active = shouldPlayBlockingTone();
  state.blockingToneGain.gain.cancelScheduledValues(now);
  state.blockingToneGain.gain.setTargetAtTime(active ? 0.013 : 0, now, 0.03);
}

function playRogerBeep() {
  if (!state.audioCtx) {
    return;
  }

  const ctx = state.audioCtx;
  const out = state.masterOutput || ctx.destination;
  const now = ctx.currentTime;

  if (now - state.lastRogerAt < 0.14) {
    return;
  }
  state.lastRogerAt = now;

  if (state.rogerBeepBuffer) {
    const sampleSource = ctx.createBufferSource();
    sampleSource.buffer = state.rogerBeepBuffer;

    const sampleGain = ctx.createGain();
    sampleGain.gain.setValueAtTime(0.95, now);

    sampleSource.connect(sampleGain);
    sampleGain.connect(out);
    sampleSource.start(now);

    setTimeout(() => {
      try {
        sampleGain.disconnect();
      } catch (_err) {
        // Ignore sample beep cleanup race conditions.
      }
    }, 400);
    return;
  }

  if (!state.rogerBeepLoading) {
    loadRogerBeepSample().catch(() => {
      // Ignore lazy load failures and keep fallback tone.
    });
  }

  const beepOsc = ctx.createOscillator();
  beepOsc.type = "sine";
  beepOsc.frequency.setValueAtTime(1880, now);
  beepOsc.frequency.setValueAtTime(1450, now + 0.05);

  const beepBandpass = ctx.createBiquadFilter();
  beepBandpass.type = "bandpass";
  beepBandpass.frequency.value = 1650;
  beepBandpass.Q.value = 1.2;

  const beepGain = ctx.createGain();
  beepGain.gain.setValueAtTime(0.0001, now);
  beepGain.gain.exponentialRampToValueAtTime(0.085, now + 0.002);
  beepGain.gain.exponentialRampToValueAtTime(0.065, now + 0.05);
  beepGain.gain.exponentialRampToValueAtTime(0.0001, now + 0.11);

  beepOsc.connect(beepBandpass);
  beepBandpass.connect(beepGain);
  beepGain.connect(out);

  beepOsc.start(now);
  beepOsc.stop(now + 0.112);

  setTimeout(() => {
    try {
      beepBandpass.disconnect();
      beepGain.disconnect();
    } catch (_err) {
      // Ignore beep cleanup race conditions.
    }
  }, 170);
}

function playEndTransmissionTail() {
  if (!state.audioCtx) {
    return;
  }

  const ctx = state.audioCtx;
  const out = state.masterOutput || ctx.destination;
  const now = ctx.currentTime;

  if (now - state.lastEotAt < 0.18) {
    return;
  }
  state.lastEotAt = now;

  playRogerBeep();

  const tailMix = ctx.createGain();
  tailMix.gain.setValueAtTime(0.0001, now);
  tailMix.gain.exponentialRampToValueAtTime(0.1, now + 0.004);
  tailMix.gain.exponentialRampToValueAtTime(0.0001, now + 0.11);
  tailMix.connect(out);

  const burst = ctx.createBufferSource();
  burst.buffer = createCrackleBuffer(ctx, 0.12);

  const burstHighpass = ctx.createBiquadFilter();
  burstHighpass.type = "highpass";
  burstHighpass.frequency.value = 1700;

  const burstLowpass = ctx.createBiquadFilter();
  burstLowpass.type = "lowpass";
  burstLowpass.frequency.value = 5000;

  const burstGain = ctx.createGain();
  burstGain.gain.setValueAtTime(0.0001, now);
  burstGain.gain.exponentialRampToValueAtTime(0.32, now + 0.006);
  burstGain.gain.exponentialRampToValueAtTime(0.0001, now + 0.06);

  const chirp = ctx.createOscillator();
  chirp.type = "triangle";
  chirp.frequency.setValueAtTime(1450, now);
  chirp.frequency.exponentialRampToValueAtTime(900, now + 0.1);

  const chirpGain = ctx.createGain();
  chirpGain.gain.setValueAtTime(0.0001, now);
  chirpGain.gain.exponentialRampToValueAtTime(0.018, now + 0.004);
  chirpGain.gain.exponentialRampToValueAtTime(0.0001, now + 0.055);

  burst.connect(burstHighpass);
  burstHighpass.connect(burstLowpass);
  burstLowpass.connect(burstGain);
  burstGain.connect(tailMix);

  chirp.connect(chirpGain);
  chirpGain.connect(tailMix);

  burst.start(now);
  burst.stop(now + 0.12);
  chirp.start(now);
  chirp.stop(now + 0.11);

  setTimeout(() => {
    try {
      tailMix.disconnect();
      burstGain.disconnect();
      chirpGain.disconnect();
      burstHighpass.disconnect();
      burstLowpass.disconnect();
    } catch (_err) {
      // Ignore tail cleanup race conditions.
    }
  }, 160);
}

function playPttClick(isDown) {
  if (!state.audioCtx) {
    return;
  }

  const ctx = state.audioCtx;
  const out = state.masterOutput || ctx.destination;
  const now = ctx.currentTime;

  const clickMix = ctx.createGain();
  clickMix.gain.setValueAtTime(0.0001, now);
  clickMix.gain.exponentialRampToValueAtTime(isDown ? 0.038 : 0.03, now + 0.002);
  clickMix.gain.exponentialRampToValueAtTime(0.0001, now + 0.03);
  clickMix.connect(out);

  const clickOsc = ctx.createOscillator();
  clickOsc.type = "triangle";
  clickOsc.frequency.setValueAtTime(isDown ? 1750 : 1320, now);
  clickOsc.frequency.exponentialRampToValueAtTime(isDown ? 980 : 760, now + 0.028);

  const toneFilter = ctx.createBiquadFilter();
  toneFilter.type = "highpass";
  toneFilter.frequency.value = 580;

  const toneGain = ctx.createGain();
  toneGain.gain.setValueAtTime(0.0001, now);
  toneGain.gain.exponentialRampToValueAtTime(0.12, now + 0.0015);
  toneGain.gain.exponentialRampToValueAtTime(0.0001, now + 0.028);

  clickOsc.connect(toneFilter);
  toneFilter.connect(toneGain);
  toneGain.connect(clickMix);

  clickOsc.start(now);
  clickOsc.stop(now + 0.03);

  setTimeout(() => {
    try {
      clickMix.disconnect();
      toneFilter.disconnect();
      toneGain.disconnect();
    } catch (_err) {
      // Ignore click cleanup race conditions.
    }
  }, 80);
}

function playUiClick() {
  if (!state.audioCtx) {
    return;
  }

  const ctx = state.audioCtx;
  const out = ctx.destination; // bypass volume knob path
  const now = ctx.currentTime;

  const mix = ctx.createGain();
  mix.gain.setValueAtTime(0.0001, now);
  mix.gain.exponentialRampToValueAtTime(0.11, now + 0.0015);
  mix.gain.exponentialRampToValueAtTime(0.0001, now + 0.028);
  mix.connect(out);

  const osc = ctx.createOscillator();
  osc.type = "triangle";
  osc.frequency.setValueAtTime(1650, now);
  osc.frequency.exponentialRampToValueAtTime(900, now + 0.025);

  const hp = ctx.createBiquadFilter();
  hp.type = "highpass";
  hp.frequency.value = 650;

  const gain = ctx.createGain();
  gain.gain.setValueAtTime(0.0001, now);
  gain.gain.exponentialRampToValueAtTime(0.2, now + 0.0015);
  gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.026);

  osc.connect(hp);
  hp.connect(gain);
  gain.connect(mix);

  osc.start(now);
  osc.stop(now + 0.03);

  setTimeout(() => {
    try {
      mix.disconnect();
      hp.disconnect();
      gain.disconnect();
    } catch (_err) {
      // Ignore UI click cleanup race conditions.
    }
  }, 90);
}

// Builds the walkie-talkie effects chain that inbound audio is played through.
// Shared by both transports: WebRTC feeds it from a MediaStreamSource, while the
// binary relay feeds it from scheduled PCM buffers.
function ensurePeerRadioChain(peer) {
  if (!state.audioCtx) {
    return;
  }

  if (!peer.peerGainNode) {
    peer.peerGainNode = state.audioCtx.createGain();
    peer.peerGainNode.gain.value = 0;

    // ── Pre-amp: boost input into clipping stage ──────────────────────
    const preGain = state.audioCtx.createGain();
    preGain.gain.value = 3.5;

    // ── Stage 1: steep highpass × 2 (12 dB + 12 dB = 24 dB/oct) ──────
    const radioHighpass = state.audioCtx.createBiquadFilter();
    radioHighpass.type = "highpass";
    radioHighpass.frequency.value = 430;
    radioHighpass.Q.value = 0.85;

    const radioHighpass2 = state.audioCtx.createBiquadFilter();
    radioHighpass2.type = "highpass";
    radioHighpass2.frequency.value = 430;
    radioHighpass2.Q.value = 0.85;

    // ── Stage 2: tighter lowpass (radio bandwidth ≈ 300-2500 Hz) ──────
    const radioLowpass = state.audioCtx.createBiquadFilter();
    radioLowpass.type = "lowpass";
    radioLowpass.frequency.value = 2450;
    radioLowpass.Q.value = 1.1;

    // ── Stage 3: cut low-mid mud ───────────────────────────────────────
    const lowMidDip = state.audioCtx.createBiquadFilter();
    lowMidDip.type = "peaking";
    lowMidDip.frequency.value = 580;
    lowMidDip.Q.value = 1.5;
    lowMidDip.gain.value = -6;

    // ── Stage 4: presence boost (intelligibility) ──────────────────────
    const presencePeak = state.audioCtx.createBiquadFilter();
    presencePeak.type = "peaking";
    presencePeak.frequency.value = 1900;
    presencePeak.Q.value = 1.8;
    presencePeak.gain.value = 7;

    // ── Stage 5: speaker-box resonance (~1.1 kHz honk) ────────────────
    const boxResonance = state.audioCtx.createBiquadFilter();
    boxResonance.type = "peaking";
    boxResonance.frequency.value = 1100;
    boxResonance.Q.value = 3.2;
    boxResonance.gain.value = 4;

    // ── Stage 6: hard RF saturation ───────────────────────────────────
    const radioDrive = state.audioCtx.createWaveShaper();
    radioDrive.curve = createRadioSaturationCurve(260);
    radioDrive.oversample = "4x";

    // ── Stage 7: post-clip bandpass to clean out-of-band artifacts ────
    const postHP = state.audioCtx.createBiquadFilter();
    postHP.type = "highpass";
    postHP.frequency.value = 380;
    postHP.Q.value = 0.7;

    const postLP = state.audioCtx.createBiquadFilter();
    postLP.type = "lowpass";
    postLP.frequency.value = 2700;
    postLP.Q.value = 0.7;

    // ── Stage 8: brutal AGC (real radio limiter) ───────────────────────
    const radioCompressor = state.audioCtx.createDynamicsCompressor();
    radioCompressor.threshold.value = -20;
    radioCompressor.knee.value = 3;
    radioCompressor.ratio.value = 16;
    radioCompressor.attack.value = 0.001;
    radioCompressor.release.value = 0.055;

    const radioBoost = state.audioCtx.createGain();
    radioBoost.gain.value = 1.6;

    const rxAnalyser = state.audioCtx.createAnalyser();
    rxAnalyser.fftSize = 256;
    rxAnalyser.smoothingTimeConstant = 0.7;

    peer.peerGainNode.connect(preGain);
    preGain.connect(radioHighpass);
    radioHighpass.connect(radioHighpass2);
    radioHighpass2.connect(radioLowpass);
    radioLowpass.connect(lowMidDip);
    lowMidDip.connect(presencePeak);
    presencePeak.connect(boxResonance);
    boxResonance.connect(radioDrive);
    radioDrive.connect(postHP);
    postHP.connect(postLP);
    postLP.connect(radioCompressor);
    radioCompressor.connect(radioBoost);
    radioBoost.connect(rxAnalyser);
    rxAnalyser.connect(state.masterOutput || state.audioCtx.destination);

    peer.radioHighpass = radioHighpass;
    peer.radioLowpass = radioLowpass;
    peer.lowMidDip = lowMidDip;
    peer.presencePeak = presencePeak;
    peer.radioDrive = radioDrive;
    peer.radioCompressor = radioCompressor;
    peer.radioBoost = radioBoost;
    peer.rxAnalyserNode = rxAnalyser;
  }
}

function connectPeerAudio(peer, stream) {
  if (!state.audioCtx) {
    return;
  }

  if (peer.sourceNode) {
    try {
      peer.sourceNode.disconnect();
    } catch (_err) {
      // Ignore stale graph disconnection errors from previous tracks.
    }
  }

  ensurePeerRadioChain(peer);

  peer.sourceNode = state.audioCtx.createMediaStreamSource(stream);
  peer.sourceNode.connect(peer.peerGainNode);
}

/* ── RELAY_TRANSPORT: binary PCM over the signalling socket ─────────────
 * The in-game OpenBVE client has no WebRTC stack, so it exchanges audio as
 * raw PCM frames on the same WebSocket used for signalling. Wire format is
 * fixed by VoiceClient.AudioFormat: 16 kHz, 16-bit signed little-endian, mono.
 *
 * The server routes any given pair of clients over exactly one transport —
 * WebRTC when both ends speak it, the relay whenever either end is relay-only —
 * so relay audio can never double up with the peer mesh.
 * ─────────────────────────────────────────────────────────────────────── */
const RELAY_SAMPLE_RATE = 16000;
// Jitter cushion applied before the first frame of a transmission.
const RELAY_JITTER_SEC = 0.12;
// Rebuild the play head when the incoming stream stalls or runs far ahead.
const RELAY_RESYNC_SEC = 0.35;

let relayCaptureNode = null;
let relayCaptureSource = null;
let relayCaptureFilter = null;
let relayCaptureSink = null;
let relayResampleCarry = 0;

// True when a relay-only peer is listening on the channel we transmit on.
// Browser-to-browser audio stays on WebRTC, so there is no reason to spend
// upstream bandwidth on PCM unless a game client is actually there to hear it.
function hasRelayPeersOnChannel() {
  for (const peer of state.peers.values()) {
    if (peer.transport === "relay" && peer.channel === state.selectedChannel) {
      return true;
    }
  }
  return false;
}

function ensureRelayPlayback(peer) {
  if (!state.audioCtx || peer.relayInputNode) {
    return;
  }

  ensurePeerRadioChain(peer);

  peer.relayInputNode = state.audioCtx.createGain();
  peer.relayInputNode.gain.value = 1;

  // Processed path — gated by peerGainNode exactly like WebRTC audio is.
  if (peer.peerGainNode) {
    peer.relayInputNode.connect(peer.peerGainNode);
  }

  // Unprocessed path for when the operator switches the audio filter off.
  // WebRTC peers get that through their <audio> element, which relay peers
  // have no stream to feed, so they need their own clean tap to master.
  peer.relayCleanGain = state.audioCtx.createGain();
  peer.relayCleanGain.gain.value = 0;
  peer.relayInputNode.connect(peer.relayCleanGain);
  peer.relayCleanGain.connect(state.masterOutput || state.audioCtx.destination);
}

function playRelayFrame(buffer) {
  if (!state.audioCtx) {
    return;
  }

  // Binary frames carry no sender id, but the server only relays frames from
  // the current PTT holder, so the active speaker is the sender by construction.
  const speakerId = state.activeSpeakerId;
  if (!speakerId || speakerId === state.selfId) {
    return;
  }

  const peer = state.peers.get(speakerId);
  if (!peer) {
    return;
  }

  ensureRelayPlayback(peer);
  if (!peer.relayInputNode) {
    return;
  }

  const pcm = new Int16Array(buffer);
  if (!pcm.length) {
    return;
  }

  const frame = state.audioCtx.createBuffer(1, pcm.length, RELAY_SAMPLE_RATE);
  const channelData = frame.getChannelData(0);
  for (let i = 0; i < pcm.length; i += 1) {
    channelData[i] = pcm[i] / 32768;
  }

  const source = state.audioCtx.createBufferSource();
  source.buffer = frame;
  source.connect(peer.relayInputNode);

  // Schedule back-to-back so frames play gaplessly, resyncing when the sender
  // pauses (end of transmission) or we drift too far ahead of the clock.
  const now = state.audioCtx.currentTime;
  if (
    !peer.relayPlayHead ||
    peer.relayPlayHead < now ||
    peer.relayPlayHead > now + RELAY_RESYNC_SEC
  ) {
    peer.relayPlayHead = now + RELAY_JITTER_SEC;
  }

  source.start(peer.relayPlayHead);
  peer.relayPlayHead += frame.duration;
}

// Linear resample from the AudioContext rate down to the 16 kHz wire rate,
// carrying the fractional read position across callbacks so frame boundaries
// don't click.
function resampleToRelayPcm(input, inputRate) {
  const ratio = inputRate / RELAY_SAMPLE_RATE;
  if (!(ratio > 0) || !input.length) {
    return null;
  }

  const outLength = Math.floor((input.length - relayResampleCarry) / ratio);
  if (outLength <= 0) {
    relayResampleCarry = Math.max(0, relayResampleCarry - input.length);
    return null;
  }

  const out = new Int16Array(outLength);
  let pos = relayResampleCarry;
  for (let i = 0; i < outLength; i += 1) {
    const idx = Math.floor(pos);
    const frac = pos - idx;
    const a = input[idx] || 0;
    const b = idx + 1 < input.length ? input[idx + 1] : a;
    const sample = Math.max(-1, Math.min(1, a + (b - a) * frac));
    out[i] = sample < 0 ? sample * 32768 : sample * 32767;
    pos += ratio;
  }

  relayResampleCarry = Math.max(0, pos - input.length);
  return out;
}

function startRelayCapture() {
  if (relayCaptureNode || !state.audioCtx || !state.localStream) {
    return;
  }

  const ctx = state.audioCtx;
  relayResampleCarry = 0;

  relayCaptureSource = ctx.createMediaStreamSource(state.localStream);

  // Anti-alias before decimating to 16 kHz (8 kHz Nyquist).
  relayCaptureFilter = ctx.createBiquadFilter();
  relayCaptureFilter.type = "lowpass";
  relayCaptureFilter.frequency.value = 7000;
  relayCaptureFilter.Q.value = 0.7;

  relayCaptureNode = ctx.createScriptProcessor(4096, 1, 1);
  relayCaptureNode.onaudioprocess = (event) => {
    if (!state.txGranted) {
      return;
    }
    if (!state.ws || state.ws.readyState !== WebSocket.OPEN) {
      return;
    }
    const pcm = resampleToRelayPcm(
      event.inputBuffer.getChannelData(0),
      event.inputBuffer.sampleRate
    );
    if (pcm && pcm.length) {
      state.ws.send(pcm.buffer);
    }
  };

  relayCaptureSource.connect(relayCaptureFilter);
  relayCaptureFilter.connect(relayCaptureNode);

  // A ScriptProcessor only fires while it has a downstream connection; the
  // silent sink keeps it running without feeding the operator's own voice back
  // into their earpiece.
  relayCaptureSink = ctx.createGain();
  relayCaptureSink.gain.value = 0;
  relayCaptureNode.connect(relayCaptureSink);
  relayCaptureSink.connect(ctx.destination);
}

function stopRelayCapture() {
  for (const node of [
    relayCaptureSource,
    relayCaptureFilter,
    relayCaptureNode,
    relayCaptureSink
  ]) {
    if (!node) {
      continue;
    }
    try {
      node.disconnect();
    } catch (_err) {
      // Ignore teardown races on an already-torn-down graph.
    }
  }

  if (relayCaptureNode) {
    relayCaptureNode.onaudioprocess = null;
  }

  relayCaptureSource = null;
  relayCaptureFilter = null;
  relayCaptureNode = null;
  relayCaptureSink = null;
  relayResampleCarry = 0;
}

function setStatus(message) {
  statusEl.textContent = message;
}

function setChannelState(message) {
  channelStateEl.textContent = message;
}

function updateChannelDisplay() {
  const chNameEl = document.querySelector(".apx-ch-name");
  if (chNameEl) {
    const chLabel = CHANNEL_LABELS[state.selectedChannel] || state.selectedChannel || "Operators";
    const trainId = trainIdEl ? trainIdEl.value || "----" : "----";
    chNameEl.textContent = `${chLabel} (${trainId})`;
  }
  // Update menu display
  if (menuChannelEl) {
    const chLabel = CHANNEL_LABELS[state.selectedChannel] || state.selectedChannel || "Operators";
    menuChannelEl.textContent = chLabel;
  }
  updateMenuArrows();
}

function canAccessChannel(channelId) {
  // Everyone can access operators channel
  if (channelId === "operators") return true;
  // T3, mod, and admin can access all channels
  return state.rank === "t3" || state.rank === "mod" || state.rank === "admin";
}

function setSelectedChannel(channelId) {
  if (!canAccessChannel(channelId)) {
    setStatus(`Cannot access channel: ${CHANNEL_LABELS[channelId] || channelId}`);
    return;
  }
  state.selectedChannel = channelId;
  updateChannelDisplay();
  refreshPeerList();
  if (state.ws && state.ws.readyState === WebSocket.OPEN) {
    state.ws.send(JSON.stringify({
      type: "set-channel",
      payload: { channel: channelId }
    }));
  }
}

function stepSelectedChannel(direction) {
  if (!state.availableChannels || state.availableChannels.length === 0) return;
  
  const currentIdx = state.availableChannels.findIndex(ch => ch.id === state.selectedChannel);
  let nextIdx = currentIdx === -1 ? 0 : currentIdx + direction;
  
  // Wrap around
  if (nextIdx < 0) nextIdx = state.availableChannels.length - 1;
  if (nextIdx >= state.availableChannels.length) nextIdx = 0;
  
  const nextChannel = state.availableChannels[nextIdx];
  if (nextChannel && nextChannel.allowed) {
    setSelectedChannel(nextChannel.id);
  }
}

// Menu navigation for LCD
const MENU_ITEM_COUNT = 6; // 0:channel 1:role 2:trainId 3:mic 4:output 5:ptt

function getMenuValueEls() {
  return [menuChannelEl, menuRoleEl, menuTrainIdEl, menuMicEl, menuOutputEl, menuPttEl];
}

function updateMenuArrows() {
  // Channel arrows
  if (menuChannelArrowsEl && state.availableChannels.length > 0) {
    const activeChannel = state.menuState.editMode && state.menuState.selectedItem === 0
      ? (state.menuState.channelEditValue || state.selectedChannel)
      : state.selectedChannel;
    const idx = state.availableChannels.findIndex(ch => ch.id === activeChannel);
    const hasPrev = idx > 0;
    const hasNext = idx < state.availableChannels.length - 1;
    menuChannelArrowsEl.textContent = !hasPrev && !hasNext ? "" : hasPrev && hasNext ? "◀ ▶" : hasPrev ? "◀" : "▶";
  }

  // Role arrows
  if (menuRoleArrowsEl && roleEl) {
    const total = roleEl.options.length;
    const idx = roleEl.selectedIndex;
    const hasPrev = idx > 0;
    const hasNext = idx < total - 1;
    menuRoleArrowsEl.textContent = !hasPrev && !hasNext ? "" : hasPrev && hasNext ? "◀ ▶" : hasPrev ? "◀" : "▶";
  }

  // Mic arrows
  if (menuMicArrowsEl && micSelectEl) {
    const total = micSelectEl.options.length;
    const idx = micSelectEl.selectedIndex;
    const hasPrev = idx > 0;
    const hasNext = idx < total - 1;
    menuMicArrowsEl.textContent = !hasPrev && !hasNext ? "" : hasPrev && hasNext ? "◀ ▶" : hasPrev ? "◀" : "▶";
  }

  // Output arrows
  if (menuOutputArrowsEl && outputSelectEl) {
    const total = outputSelectEl.options.length;
    const idx = outputSelectEl.selectedIndex;
    const hasPrev = idx > 0;
    const hasNext = idx < total - 1;
    menuOutputArrowsEl.textContent = !hasPrev && !hasNext ? "" : hasPrev && hasNext ? "◀ ▶" : hasPrev ? "◀" : "▶";
  }
}

function updateMenuDisplay() {
  if (menuChannelEl) {
    const channelId = state.menuState.editMode && state.menuState.selectedItem === 0
      ? (state.menuState.channelEditValue || state.selectedChannel)
      : state.selectedChannel;
    menuChannelEl.textContent = CHANNEL_LABELS[channelId] || channelId || "Operators";
  }
  if (menuRoleEl && roleEl) {
    menuRoleEl.textContent = roleEl.options[roleEl.selectedIndex]?.text || roleEl.value;
  }
  if (menuTrainIdEl && !(state.menuState.editMode && state.menuState.selectedItem === 2)) {
    menuTrainIdEl.textContent = (trainIdEl && trainIdEl.value) ? trainIdEl.value : "----";
  }
  if (menuMicEl && micSelectEl) {
    const opt = micSelectEl.options[micSelectEl.selectedIndex];
    menuMicEl.textContent = opt ? opt.text : "Default";
  }
  if (menuOutputEl && outputSelectEl) {
    const opt = outputSelectEl.options[outputSelectEl.selectedIndex];
    menuOutputEl.textContent = opt ? opt.text : "Default";
  }
  if (menuPttEl) {
    menuPttEl.textContent = friendlyKeyName ? friendlyKeyName(state.pttKeyCode) : state.pttKeyCode;
  }
  updateMenuArrows();
}

function updateMenuItemHighlight() {
  const values = getMenuValueEls();
  if (!values[0]) return;

  values.forEach(val => { if (val) { val.style.background = "transparent"; val.style.color = ""; } });

  const active = values[state.menuState.selectedItem];
  if (!active) return;

  if (state.menuState.editMode) {
    active.style.background = "rgba(30, 100, 220, 0.7)";
    active.style.color = "#fff";
  } else {
    active.style.background = "rgba(212, 160, 24, 0.7)";
  }
}

function menuCancelEdit() {
  state.menuState.editMode = false;
  state.menuState.channelEditValue = null;
  if (state.menuState.selectedItem === 2) {
    state.menuState.trainIdEditValue = "";
    if (menuTrainIdEl) {
      menuTrainIdEl.textContent = (trainIdEl && trainIdEl.value) ? trainIdEl.value : "----";
    }
  }
  updateMenuDisplay();
  updateMenuItemHighlight();
}

function menuStepItem(direction) {
  if (state.menuState.editMode) menuCancelEdit();
  state.menuState.selectedItem = (state.menuState.selectedItem + direction + MENU_ITEM_COUNT) % MENU_ITEM_COUNT;
  updateMenuItemHighlight();
}

function menuChangeCurrentItem(direction) {
  if (!state.menuState.editMode) return;

  const item = state.menuState.selectedItem;

  if (item === 0) {
    if (!state.availableChannels || state.availableChannels.length === 0) return;

    const currentId = state.menuState.channelEditValue || state.selectedChannel;
    const currentIdx = state.availableChannels.findIndex(ch => ch.id === currentId);
    let nextIdx = currentIdx === -1 ? 0 : currentIdx + direction;

    if (nextIdx < 0) nextIdx = state.availableChannels.length - 1;
    if (nextIdx >= state.availableChannels.length) nextIdx = 0;

    const nextChannel = state.availableChannels[nextIdx];
    if (!nextChannel || !nextChannel.allowed) return;

    state.menuState.channelEditValue = nextChannel.id;
    updateMenuDisplay();
  } else if (item === 1) {
    if (!roleEl) return;
    const options = Array.from(roleEl.options);
    const currentIdx = options.findIndex(opt => opt.value === roleEl.value);
    roleEl.selectedIndex = (currentIdx + direction + options.length) % options.length;
    roleEl.dispatchEvent(new Event("change"));
  } else if (item === 3) {
    if (!micSelectEl || micSelectEl.options.length === 0) return;
    const nextIdx = Math.min(Math.max(0, micSelectEl.selectedIndex + direction), micSelectEl.options.length - 1);
    micSelectEl.selectedIndex = nextIdx;
    micSelectEl.dispatchEvent(new Event("change"));
    updateMenuDisplay();
  } else if (item === 4) {
    if (!outputSelectEl || outputSelectEl.options.length === 0) return;
    const nextIdx = Math.min(Math.max(0, outputSelectEl.selectedIndex + direction), outputSelectEl.options.length - 1);
    outputSelectEl.selectedIndex = nextIdx;
    outputSelectEl.dispatchEvent(new Event("change"));
    updateMenuDisplay();
  }
}

function menuConfirmSelection() {
  const item = state.menuState.selectedItem;

  if (state.menuState.editMode) {
    if (item === 0) {
      const nextChannelId = state.menuState.channelEditValue || state.selectedChannel;
      if (nextChannelId && nextChannelId !== state.selectedChannel) {
        // Sync to server immediately on confirm.
        setSelectedChannel(nextChannelId);
      }
      state.menuState.channelEditValue = null;
    } else if (item === 2) {
      trainIdEl.value = state.menuState.trainIdEditValue;
      trainIdEl.dispatchEvent(new Event("change"));
      state.menuState.trainIdEditValue = "";
      if (menuTrainIdEl) menuTrainIdEl.textContent = trainIdEl.value || "----";
    }
    // For PTT (5): edit mode is listening for a key; OK while capturing does nothing
    if (item !== 5) {
      state.menuState.editMode = false;
      updateMenuItemHighlight();
    }
  } else {
    state.menuState.editMode = true;

    if (item === 0) {
      state.menuState.channelEditValue = state.selectedChannel;
      updateMenuDisplay();
    } else if (item === 2) {
      state.menuState.trainIdEditValue = "";
      if (menuTrainIdEl) menuTrainIdEl.textContent = "----";
    } else if (item === 5) {
      // Start PTT capture
      if (menuPttEl) menuPttEl.textContent = "Press key…";
      updateMenuItemHighlight();
      function onCapture(e) {
        e.preventDefault();
        e.stopPropagation();
        if (["Shift", "Control", "Alt", "Meta"].includes(e.key)) return;
        state.pttKeyCode = e.code;
        saveSettings();
        if (pttKeyCaptureEl) pttKeyCaptureEl.textContent = friendlyKeyName(e.code);
        if (menuPttEl) menuPttEl.textContent = friendlyKeyName(e.code);
        setStatus(`PTT key set to ${friendlyKeyName(e.code)}`);
        state.menuState.editMode = false;
        updateMenuItemHighlight();
        window.removeEventListener("keydown", onCapture, true);
      }
      window.addEventListener("keydown", onCapture, true);
    }

    updateMenuItemHighlight();
  }
}

function menuNumberKeypad(digit) {
  if (state.menuState.selectedItem === 2 && state.menuState.editMode) {
    state.menuState.trainIdEditValue += digit;
    if (menuTrainIdEl) menuTrainIdEl.textContent = state.menuState.trainIdEditValue;
  }
}

function setKnobRotation(el, level) {
  if (!el) return;
  const deg = -120 + (Math.max(0, Math.min(1, level)) * 240);
  el.style.setProperty("--knob-rot", `${deg}deg`);
}

function applyVolumeState() {
  if (state.masterOutput) {
    state.masterOutput.gain.value = state.masterVolume;
  }

  for (const peer of state.peers.values()) {
    if (peer.peerGainNode && !state.cleanMonitorEnabled) {
      peer.peerGainNode.gain.value = state.rxVolume;
    }
    if (peer.audio && state.cleanMonitorEnabled) {
      peer.audio.volume = state.rxVolume;
    }
    // Track volume changes on an in-progress relay transmission without
    // un-gating a peer that routePeerAudio has currently silenced.
    if (
      peer.relayCleanGain &&
      state.cleanMonitorEnabled &&
      peer.relayCleanGain.gain.value > 0
    ) {
      peer.relayCleanGain.gain.value = state.rxVolume;
    }
  }

  setKnobRotation(volKnobEl, state.masterVolume);
  if (volumeValueEl) {
    volumeValueEl.textContent = `${Math.round(state.masterVolume * 100)}%`;
  }
}

function updateTxLight() {
  if (!txLightEl) return;
  if (state.txGranted) {
    txLightEl.className = "tx-light tx";
  } else if (state.activeSpeakerId && state.activeSpeakerId !== state.selfId) {
    txLightEl.className = "tx-light rx";
  } else {
    txLightEl.className = "tx-light idle";
  }
}

function setupKnobControl(el, key) {
  if (!el) return;

  const setLevel = (level) => {
    const next = Math.round(Math.max(0, Math.min(1, level)) * 10) / 10;
    if (next === state[key]) {
      return;
    }

    state[key] = next;
    if (key === "masterVolume") {
      state.rxVolume = state[key];
    }

    initAudioEngine();
    playUiClick();
    applyVolumeState();
    saveSettings();
  };

  el.addEventListener("wheel", (event) => {
    event.preventDefault();
    const delta = event.deltaY > 0 ? -0.1 : 0.1;
    setLevel(state[key] + delta);
  }, { passive: false });

  let dragStartY = 0;
  let dragStartLevel = 0;
  el.addEventListener("pointerdown", (event) => {
    dragStartY = event.clientY;
    dragStartLevel = state[key];
    el.setPointerCapture(event.pointerId);

    const onMove = (moveEvent) => {
      const dy = dragStartY - moveEvent.clientY;
      setLevel(dragStartLevel + (dy / 200));
    };

    const onUp = (upEvent) => {
      el.releasePointerCapture(upEvent.pointerId);
      el.removeEventListener("pointermove", onMove);
      el.removeEventListener("pointerup", onUp);
      el.removeEventListener("pointercancel", onUp);
    };

    el.addEventListener("pointermove", onMove);
    el.addEventListener("pointerup", onUp);
    el.addEventListener("pointercancel", onUp);
  });
}

function wsSend(type, payload) {
  if (!state.ws || state.ws.readyState !== WebSocket.OPEN) {
    return;
  }

  state.ws.send(JSON.stringify({ type, payload }));
}

function getOnlineRoleClass(rank, role) {
  const normalizedRank = String(rank || "").toLowerCase();
  const normalizedRole = String(role || "").toLowerCase();

  if (normalizedRank === "admin") return "role-admin";
  if (normalizedRank === "mod") return "role-mod";
  if (normalizedRank === "t3") return "role-t3";
  if (normalizedRank === "t2") return "role-t2";
  if (normalizedRank === "t1") return "role-t1";

  if (normalizedRole === "dispatcher") return "role-dispatcher";
  if (normalizedRole === "operator") return "role-operator";
  if (normalizedRole === "listener") return "role-listener";
  return "";
}

function refreshPeerList() {
  if (!peersEl) return;
  peersEl.innerHTML = "";

  const entries = [...state.peers.entries()];
  const hasSelf = Boolean(state.selfId);

  const grouped = new Map();

  const addUserToGroup = (channelId, userHtml, isTxActive, roleClass) => {
    const key = channelId || DEFAULT_CHANNEL;
    if (!grouped.has(key)) {
      grouped.set(key, []);
    }
    grouped.get(key).push({ userHtml, isTxActive, roleClass });
  };

  if (hasSelf) {
    const selfTxActive = state.txGranted || state.currentHolderId === state.selfId || state.activeSpeakerId === state.selfId;
    addUserToGroup(
      state.selectedChannel || DEFAULT_CHANNEL,
      `${escapeHtml(state.selfName || "You")} (${RANK_LABELS[state.rank] || state.rank}) (You)`,
      selfTxActive,
      getOnlineRoleClass(state.rank, state.selfRole)
    );
  }

  for (const [peerId, peer] of entries) {
    const isTxActive = state.currentHolderId === peerId || state.activeSpeakerId === peerId;
    addUserToGroup(
      peer.channel || DEFAULT_CHANNEL,
      `${escapeHtml(peer.name || "User")} (${RANK_LABELS[peer.rank] || peer.rank})`,
      isTxActive,
      getOnlineRoleClass(peer.rank, peer.role)
    );
  }

  const orderedChannels = (state.availableChannels && state.availableChannels.length > 0)
    ? state.availableChannels.map(channel => channel.id)
    : Object.keys(CHANNEL_LABELS);

  for (const channelId of grouped.keys()) {
    if (!orderedChannels.includes(channelId)) orderedChannels.push(channelId);
  }

  for (const channelId of orderedChannels) {
    const header = document.createElement("li");
    header.className = "member-channel-header";
    header.textContent = CHANNEL_LABELS[channelId] || channelId;
    peersEl.appendChild(header);

    const users = grouped.get(channelId) || [];
    for (const user of users) {
      const li = document.createElement("li");
      li.className = `member-online-item ${user.roleClass || ""}`.trim();
      li.innerHTML = `
        <span class="member-online-name">${user.userHtml}</span>
        <span class="tx-badge ${user.isTxActive ? "active" : ""}">TX</span>
      `;
      peersEl.appendChild(li);
    }
  }
}

function ensurePeer(peerInfo) {
  if (state.peers.has(peerInfo.id)) {
    const existing = state.peers.get(peerInfo.id);
    if (typeof peerInfo.name === "string" && peerInfo.name.trim()) {
      existing.name = peerInfo.name;
    }
    if (typeof peerInfo.role === "string" && peerInfo.role.trim()) {
      existing.role = peerInfo.role;
    }
    if (typeof peerInfo.channel === "string" && peerInfo.channel.trim()) {
      existing.channel = peerInfo.channel;
    }
    if (typeof peerInfo.rank === "string" && peerInfo.rank.trim()) {
      existing.rank = peerInfo.rank;
    }
    if (typeof peerInfo.transport === "string" && peerInfo.transport.trim()) {
      existing.transport = peerInfo.transport === "relay" ? "relay" : "webrtc";
    }
    return existing;
  }

  // Relay-only peers (the in-game client) have no WebRTC stack, so there is no
  // peer connection to negotiate — their audio arrives as PCM frames over the
  // WebSocket instead. See RELAY_TRANSPORT below.
  const transport = peerInfo.transport === "relay" ? "relay" : "webrtc";
  const pc = transport === "relay" ? null : new RTCPeerConnection(stunConfig);

  if (pc && state.localStream) {
    for (const track of state.localStream.getTracks()) {
      pc.addTrack(track, state.localStream);
    }
  }

  const audio = document.createElement("audio");
  audio.autoplay = true;
  audio.playsInline = true;
  audio.muted = true;
  audio.volume = 0;
  applyAudioOutputSink(audio);

  if (pc) {
    pc.ontrack = (event) => {
      audio.srcObject = event.streams[0];
      audio.play().catch(() => {
        // Playback may need a user gesture on some browsers.
      });
      connectPeerAudio(peer, event.streams[0]);
    };

    pc.onicecandidate = (event) => {
      if (!event.candidate) {
        return;
      }

      wsSend("signal", {
        to: peerInfo.id,
        data: {
          candidate: event.candidate
        }
      });
    };
  }

  const peer = {
    id: peerInfo.id,
    name: (typeof peerInfo.name === "string" && peerInfo.name.trim()) ? peerInfo.name : "User",
    role: (typeof peerInfo.role === "string" && peerInfo.role.trim()) ? peerInfo.role : "operator",
    rank: (typeof peerInfo.rank === "string" && peerInfo.rank.trim()) ? peerInfo.rank : "t1",
    channel: (typeof peerInfo.channel === "string" && peerInfo.channel.trim()) ? peerInfo.channel : "operators",
    transport,
    pc,
    audio,
    sourceNode: null,
    peerGainNode: null,
    relayInputNode: null,
    relayCleanGain: null,
    relayPlayHead: 0,
    radioHighpass: null,
    radioLowpass: null,
    lowMidDip: null,
    presencePeak: null,
    radioDrive: null,
    radioCompressor: null,
    radioBoost: null,
    rxAnalyserNode: null
  };

  state.peers.set(peerInfo.id, peer);
  refreshPeerList();
  return peer;
}

async function createOffer(peerInfo) {
  const peer = ensurePeer(peerInfo);
  if (!peer.pc) {
    // Relay-only peer — nothing to negotiate.
    return;
  }
  const offer = await peer.pc.createOffer();
  await peer.pc.setLocalDescription(offer);

  wsSend("signal", {
    to: peer.id,
    data: {
      description: peer.pc.localDescription
    }
  });
}

async function handleSignal(from, data) {
  const peer = ensurePeer({ id: from, role: "operator" });
  if (!peer.pc) {
    // A relay-only peer should never signal; ignore it rather than throwing.
    return;
  }

  if (data.description) {
    const desc = data.description;
    await peer.pc.setRemoteDescription(desc);

    if (desc.type === "offer") {
      const answer = await peer.pc.createAnswer();
      await peer.pc.setLocalDescription(answer);
      wsSend("signal", {
        to: from,
        data: {
          description: peer.pc.localDescription
        }
      });
    }
    return;
  }

  if (data.candidate) {
    await peer.pc.addIceCandidate(data.candidate);
  }
}

function applyTxState(payload) {
  state.activeSpeakerId = payload.active ? payload.speakerId : null;
  state.activeChannel = payload.active ? payload.channel : null;
  let isReceivingAudio = false;

  // Only listen if we're on the same channel as the speaker
  const isListenerOnChannel = state.selectedChannel === payload.channel;

  for (const [peerId, peer] of state.peers.entries()) {
    if (payload.active && peerId === payload.speakerId && isListenerOnChannel) {
      routePeerAudio(peer, true);
      isReceivingAudio = true;
    } else {
      routePeerAudio(peer, false);
    }
  }

  const startedTransmission = !state.lastRxActive && isReceivingAudio;
  const endedTransmission = state.lastRxActive && !isReceivingAudio && !state.txGranted;

  if (startedTransmission) {
    playSquelchOpen();
    updateNoiseLevel(true);
  } else if (endedTransmission) {
    playEndTransmissionTail();
    playSquelchClose(); // schedules noise burst+cut; skip updateNoiseLevel(false)
  } else {
    updateNoiseLevel(isReceivingAudio);
  }

  state.lastRxActive = isReceivingAudio;
  syncBlockingTone();
  refreshPeerList();
  updateTxLight();

  if (!payload.active) {
    setChannelState("Channel idle");
    return;
  }

  if (payload.speakerId !== state.selfId) {
    setChannelState("RX");
  }
}

function setTx(enabled) {
  state.txGranted = enabled;
  if (state.localTrack) {
    state.localTrack.enabled = enabled;
  }

  // Mirror the transmission onto the PCM relay so relay-only peers (the in-game
  // client) can hear it. WebRTC peers are already covered by the mesh.
  if (enabled && hasRelayPeersOnChannel()) {
    startRelayCapture();
  } else if (!enabled) {
    stopRelayCapture();
  }

  if (enabled) {
    pttBtn.classList.add("active");
    setStatus("Transmitting");
  } else {
    pttBtn.classList.remove("active");
    setStatus("Connected (listening)");
  }

  updateSelfStatus();
  syncBlockingTone();
  updateTxLight();
}

function updatePresence() {
  wsSend("set-presence", {
    role: roleEl ? roleEl.value : undefined,
    trainId: trainIdEl.value
  });
}

async function getMicrophoneStream() {
  const constraints = {
    audio: {
      echoCancellation: true,
      noiseSuppression: true,
      autoGainControl: true,
      ...(state.selectedMicDeviceId ? { deviceId: { exact: state.selectedMicDeviceId } } : {})
    }
  };

  if (navigator.mediaDevices && typeof navigator.mediaDevices.getUserMedia === "function") {
    try {
      return await navigator.mediaDevices.getUserMedia(constraints);
    } catch (err) {
      if (!state.selectedMicDeviceId) {
        throw err;
      }

      state.selectedMicDeviceId = "";
      if (micSelectEl) {
        micSelectEl.value = "";
      }
      saveSettings();
      setStatus("Selected microphone unavailable, using default mic");

      return navigator.mediaDevices.getUserMedia({
        audio: {
          echoCancellation: true,
          noiseSuppression: true,
          autoGainControl: true
        }
      });
    }
  }

  const legacyGetUserMedia =
    navigator.getUserMedia || navigator.webkitGetUserMedia || navigator.mozGetUserMedia;

  if (typeof legacyGetUserMedia === "function") {
    return new Promise((resolve, reject) => {
      legacyGetUserMedia.call(navigator, constraints, resolve, reject);
    });
  }

  const host = String(location.hostname || "").toLowerCase();
  const isLikelyInsecure = !window.isSecureContext && host !== "localhost" && host !== "127.0.0.1";

  if (isLikelyInsecure) {
    throw new Error("Microphone requires HTTPS on phones. Open this app over HTTPS.");
  }

  throw new Error("Microphone API is not available on this browser.");
}

function createBoostedMicrophoneStream(rawStream) {
  // Mirror mic stream into an analyser so LCD can show local TX level.
  if (state.audioCtx && rawStream.getAudioTracks().length > 0) {
    if (state.micAnalyserSourceNode) {
      try {
        state.micAnalyserSourceNode.disconnect();
      } catch (_err) {
        // Ignore stale analyser source teardown errors.
      }
      state.micAnalyserSourceNode = null;
    }

    state.micAnalyserNode = state.audioCtx.createAnalyser();
    state.micAnalyserNode.fftSize = 256;
    state.micAnalyserNode.smoothingTimeConstant = 0.75;

    state.micAnalyserSourceNode = state.audioCtx.createMediaStreamSource(rawStream);
    state.micAnalyserSourceNode.connect(state.micAnalyserNode);
  }

  // Return the raw stream unmodified to preserve audio quality
  return rawStream;
}

function startMicVisualization() {
  if (state.micVisualizerAnimationId) {
    cancelAnimationFrame(state.micVisualizerAnimationId);
  }

  const canvas = document.getElementById("micCanvas");
  if (!canvas) return;

  function animateVisualizer() {
    drawMicVisualizer(canvas);
    state.micVisualizerAnimationId = requestAnimationFrame(animateVisualizer);
  }

  animateVisualizer();
}

function drawMicVisualizer(canvas) {
  if (!canvas) return;

  let analyser = null;
  const isReceiverRx = Boolean(
    state.lastRxActive &&
    state.activeSpeakerId &&
    state.selfId &&
    state.activeSpeakerId !== state.selfId &&
    !state.isPttPressed &&
    !state.txGranted
  );

  if (isReceiverRx) {
    const activePeer = state.peers.get(state.activeSpeakerId);
    if (activePeer && activePeer.rxAnalyserNode) {
      analyser = activePeer.rxAnalyserNode;
    }
  }

  if (!analyser && !isReceiverRx) {
    analyser = state.micAnalyserNode;
  }

  if (!analyser) return;

  const ctx = canvas.getContext("2d");
  const bufferLength = analyser.frequencyBinCount;
  const dataArray = new Uint8Array(bufferLength);

  analyser.getByteFrequencyData(dataArray);

  const width = canvas.width;
  const height = canvas.height;

  // Calculate average level
  let sum = 0;
  for (let i = 0; i < bufferLength; i++) {
    sum += dataArray[i];
  }
  const average = sum / bufferLength;
  const level = Math.min(1.0, average / 255);

  // Clear canvas
  ctx.fillStyle = "#91a37e";
  ctx.fillRect(0, 0, width, height);

  // Draw bars with color grading
  const barWidth = width / bufferLength * 2.5;
  let x = 0;

  for (let i = 0; i < bufferLength; i++) {
    const barHeight = (dataArray[i] / 255) * height;

    // LCD-styled color range: muted green -> olive -> deep amber
    let color;
    const normalizedHeight = barHeight / height;
    if (normalizedHeight < 0.42) {
      color = "#2b4d24";
    } else if (normalizedHeight < 0.76) {
      color = "#4c6a34";
    } else {
      color = "#6c6418";
    }

    ctx.fillStyle = color;
    ctx.fillRect(x, height - barHeight, barWidth, barHeight);

    x += barWidth;
  }

  // Draw level indicator at bottom
  const levelWidth = (width * level);
  const levelGradient = ctx.createLinearGradient(0, height - 4, levelWidth, height - 4);
  
  if (level < 0.42) {
    levelGradient.addColorStop(0, "#2b4d24");
    levelGradient.addColorStop(1, "#355a2b");
  } else if (level < 0.76) {
    levelGradient.addColorStop(0, "#355a2b");
    levelGradient.addColorStop(1, "#4f6f36");
  } else {
    levelGradient.addColorStop(0, "#4f6f36");
    levelGradient.addColorStop(1, "#6c6418");
  }

  ctx.fillStyle = levelGradient;
  ctx.fillRect(0, height - 3, levelWidth, 3);
}

async function join(roomId, userName) {
  if (state.ws) {
    state.ws.close();
  }

  const authed = await ensureAuthenticated();
  if (!authed) {
    setPowerState("off");
    setServerStatus("Server: auth required");
    return;
  }

  setPowerState("connecting");

  initAudioEngine();
  const rawStream = await getMicrophoneStream();
  state.localStream = createBoostedMicrophoneStream(rawStream);
  state.localTrack = state.localStream.getAudioTracks()[0];
  state.localTrack.enabled = false;

  const wsProtocol = location.protocol === "https:" ? "wss" : "ws";
  const wsBaseUrl = `${wsProtocol}://${location.host}`;
  const wsUrl = wsBaseUrl; // auth is cookie-based
  state.ws = new WebSocket(wsUrl);
  // Relayed PCM arrives as binary; ArrayBuffer lets us decode it synchronously.
  state.ws.binaryType = "arraybuffer";

  state.ws.onopen = () => {
    setPowerState("on");
    setServerStatus("Server: online (connected)");
    setUserStatus("User: joining...");

    wsSend("join", {
      roomId: roomId || state.currentRoom || "mta-main",
      userName: userName || undefined,
      role: roleEl.value,
      trainId: trainIdEl.value,
      transport: "webrtc"
    });

    setStatus("Joining room...");
  };

  state.ws.onclose = (event) => {
    setPowerState("off");
    setServerStatus("Server: checking...");
    const closeCode = event && typeof event.code === "number" ? event.code : 0;
    const closeReason = event && event.reason ? ` (${event.reason})` : "";
    setStatus(`Disconnected [${closeCode}]${closeReason}`);
    pttBtn.disabled = true;
    setTx(false);
    updateNoiseLevel(false);

    if (state.micVisualizerAnimationId) {
      cancelAnimationFrame(state.micVisualizerAnimationId);
      state.micVisualizerAnimationId = null;
    }
    if (state.micAnalyserSourceNode) {
      try {
        state.micAnalyserSourceNode.disconnect();
      } catch (_err) {
        // Ignore analyser cleanup errors.
      }
      state.micAnalyserSourceNode = null;
    }

    state.selfId = null;
    state.selfName = "";
    state.currentHolderId = null;
    state.currentQueue = [];
    state.activeSpeakerId = null;
    state.activeChannel = null;
    state.peers.clear();
    refreshPeerList();
    updateSelfStatus();
    syncBlockingTone();
    probeServerStatus();

    // Hide admin sidebar and roster modal on disconnect
    if (adminSidebarEl) adminSidebarEl.hidden = true;
    if (memberSidebarEl) memberSidebarEl.hidden = true;
    if (serverAdminTabBtnEl) {
      serverAdminTabBtnEl.hidden = true;
      serverAdminTabBtnEl.classList.remove("active");
    }
    if (rosterModalEl) rosterModalEl.hidden = true;
    if (rosterBtnWrapEl) rosterBtnWrapEl.hidden = true;
    if (adminPageBtn) adminPageBtn.hidden = true;
  };

  state.ws.onerror = () => {
    setPowerState("off");
    setServerStatus("Server: checking...");
    setStatus("WebSocket handshake failed");
    syncBlockingTone();
    probeServerStatus();
  };

  state.ws.onmessage = async (event) => {
    // Binary frames are relayed PCM audio from a relay-only peer, not JSON.
    if (typeof event.data !== "string") {
      playRelayFrame(event.data);
      return;
    }

    const msg = JSON.parse(event.data);

    if (msg.type === "joined") {
      state.selfId = msg.payload.self.id;
      state.selfName = msg.payload.self.name || "";
      state.selfRole = msg.payload.self.role || "listener";
      state.rank     = msg.payload.rank || "t1";
      state.isAdmin  = msg.payload.isAdmin || false;
      state.isMod    = msg.payload.isMod   || false;
      state.isT1     = msg.payload.isT1    !== false ? (state.rank === "t1") : false;
      state.currentRoom = msg.payload.roomId;
      state.currentRoomName = msg.payload.roomName || "Radio";
      state.currentCreatorId = msg.payload.creatorId;

      // Update server name display
      if (serverNameEl) {
        serverNameEl.textContent = state.currentRoomName;
      }

      // Set auto-assigned train ID from server
      if (msg.payload.self.trainId && trainIdEl) {
        trainIdEl.value = msg.payload.self.trainId;
      }

      // Keep role selector synced with server role/rank
      syncRoleSettingOnRadio();
      
      // Setup available channels from server
      if (Array.isArray(msg.payload.channels)) {
        state.availableChannels = msg.payload.channels;
        // Set selected channel to first allowed channel
        const firstAllowed = state.availableChannels.find(ch => ch.allowed);
        if (firstAllowed) {
          state.selectedChannel = firstAllowed.id;
          updateChannelDisplay();
        }
      }
      
      pttBtn.disabled = false;
      setStatus(`Connected as ${msg.payload.self.name}${state.isT1 ? ' (T1 \u2014 no TX)' : ''}`);
      
      // T1 rank cannot transmit
      if (state.isT1) {
        pttBtn.disabled = true;
        pttBtn.title = 'Ask an admin to assign you a higher rank to transmit';
      }
      
      // Update transmission light
      updateTxLight();
      
      // Always show admin sidebar for staff when connected
      if (adminSidebarEl) {
        adminSidebarEl.hidden = !(state.isAdmin || state.isMod);
        if (!adminSidebarEl.hidden) loadAdminMembers();
      }
      if (memberSidebarEl) {
        memberSidebarEl.hidden = false;
      }
      if (rosterBtnWrapEl) {
        rosterBtnWrapEl.hidden = !(state.isAdmin || state.isMod);
      }
      if (serverAdminTabBtnEl) {
        const canAdmin = state.isAdmin || state.isMod;
        serverAdminTabBtnEl.hidden = !canAdmin;
        serverAdminTabBtnEl.classList.toggle("active", canAdmin && adminSidebarEl && !adminSidebarEl.hidden);
      }
      if (adminPageBtn) {
        adminPageBtn.hidden = !(state.isAdmin || state.isMod);
      }
      
      // Hide room selection modal
      if (roomSelectionModalEl) {
        roomSelectionModalEl.classList.remove('active');
      }
      
      initAudioEngine();
      startMicVisualization();
      updateChannelDisplay(); // Update to show auto-assigned train ID in title
      updateMenuDisplay();    // Show auto-assigned train ID in TID menu row
      refreshPeerList();
      updateSelfStatus();

      for (const peerInfo of msg.payload.peers) {
        await createOffer(peerInfo);
      }

      return;
    }

    if (msg.type === "peer-joined") {
      ensurePeer(msg.payload);
      refreshPeerList();
      if (adminSidebarEl && !adminSidebarEl.hidden) loadAdminMembers();
      return;
    }

    if (msg.type === "peer-updated") {
      ensurePeer(msg.payload);
      refreshPeerList();
      return;
    }

    if (msg.type === "channel-changed") {
      const changedId = msg.payload.id;
      const changedChannel = msg.payload.channel;

      if (changedId && changedId !== state.selfId) {
        ensurePeer({ id: changedId, channel: changedChannel });
        refreshPeerList();
        return;
      }

      state.selectedChannel = changedChannel;
      updateChannelDisplay();
      refreshPeerList();
      return;
    }

    if (msg.type === "peer-left") {
      const peer = state.peers.get(msg.payload.id);
      if (peer) {
        if (peer.pc) {
          peer.pc.close();
        }
        if (peer.sourceNode) {
          try {
            peer.sourceNode.disconnect();
          } catch (_err) {
            // Ignore cleanup errors.
          }
        }
        if (peer.relayInputNode) {
          try {
            peer.relayInputNode.disconnect();
          } catch (_err) {
            // Ignore cleanup errors.
          }
        }
        if (peer.relayCleanGain) {
          try {
            peer.relayCleanGain.disconnect();
          } catch (_err) {
            // Ignore cleanup errors.
          }
        }
        if (peer.peerGainNode) {
          try {
            peer.peerGainNode.disconnect();
          } catch (_err) {
            // Ignore cleanup errors.
          }
        }
        if (peer.radioHighpass) {
          try {
            peer.radioHighpass.disconnect();
          } catch (_err) {
            // Ignore cleanup errors.
          }
        }
        if (peer.radioLowpass) {
          try {
            peer.radioLowpass.disconnect();
          } catch (_err) {
            // Ignore cleanup errors.
          }
        }
        if (peer.lowMidDip) {
          try {
            peer.lowMidDip.disconnect();
          } catch (_err) {
            // Ignore cleanup errors.
          }
        }
        if (peer.presencePeak) {
          try {
            peer.presencePeak.disconnect();
          } catch (_err) {
            // Ignore cleanup errors.
          }
        }
        if (peer.radioDrive) {
          try {
            peer.radioDrive.disconnect();
          } catch (_err) {
            // Ignore cleanup errors.
          }
        }
        if (peer.radioCompressor) {
          try {
            peer.radioCompressor.disconnect();
          } catch (_err) {
            // Ignore cleanup errors.
          }
        }
        if (peer.radioBoost) {
          try {
            peer.radioBoost.disconnect();
          } catch (_err) {
            // Ignore cleanup errors.
          }
        }
        if (peer.rxAnalyserNode) {
          try {
            peer.rxAnalyserNode.disconnect();
          } catch (_err) {
            // Ignore cleanup errors.
          }
        }
      }
      state.peers.delete(msg.payload.id);
      refreshPeerList();
      if (adminSidebarEl && !adminSidebarEl.hidden) loadAdminMembers();
      return;
    }

    if (msg.type === "signal") {
      await handleSignal(msg.payload.from, msg.payload.data);
      return;
    }

    if (msg.type === "ptt-granted") {
      setTx(true);
      setChannelState(`TX granted on ${msg.payload.channel}`);
      return;
    }

    if (msg.type === "ptt-queued") {
      setTx(false);
      setChannelState(`Queued on ${msg.payload.channel}, position ${msg.payload.position}`);
      setUserStatus(`User: queued (#${msg.payload.position})`);
      return;
    }

    if (msg.type === "ptt-released" || msg.type === "ptt-revoked") {
      setTx(false);
      cutNoiseNow();
      setChannelState(msg.type === "ptt-released" ? "TX released" : "TX revoked");
      return;
    }

    if (msg.type === "tx-state") {
      applyTxState(msg.payload);
      return;
    }

    if (msg.type === "channel-state") {
      state.currentHolderId = msg.payload.holderId || null;
      state.currentQueue = Array.isArray(msg.payload.queue) ? msg.payload.queue : [];
      refreshPeerList();
      updateSelfStatus();
      syncBlockingTone();
      return;
    }

    if (msg.type === "error") {
      setStatus(`Server error: ${msg.payload.message}`);
      return;
    }

    if (msg.type === "kicked") {
      setStatus("You were kicked from the server");
      setPowerState("off");
      if (state.ws) {
        state.ws.close();
      }
      return;
    }

    if (msg.type === "peer-session-role-changed") {
      const peer = state.peers.get(msg.payload.id);
      if (peer) {
        peer.role = msg.payload.role;
        refreshPeerList();
      }
      // If it's our own session role that changed
      if (msg.payload.id === state.selfId) {
        state.selfRole = msg.payload.role;
        syncRoleSettingOnRadio();
        const isListener = msg.payload.role === "listener";
        pttBtn.disabled = isListener;
        pttBtn.title = isListener ? 'Ask an admin to assign you a higher rank to transmit' : '';
        setStatus(`Session role updated: ${SESSION_LABELS[msg.payload.role] || msg.payload.role}`);
        if (adminSidebarEl && !adminSidebarEl.hidden) loadAdminMembers();
      }
      if (adminSidebarEl && !adminSidebarEl.hidden) loadAdminMembers();
      return;
    }

    if (msg.type === "peer-rank-changed") {
      const peer = state.peers.get(msg.payload.id);
      if (peer) {
        peer.rank = msg.payload.rank;
        peer.role = msg.payload.role;
        refreshPeerList();
      }
      // If it's our own rank that changed, update state and repopulate dropdown
      if (msg.payload.id === state.selfId) {
        state.rank     = msg.payload.rank;
        state.selfRole = msg.payload.role;
        state.isAdmin  = msg.payload.rank === "admin";
        state.isMod    = msg.payload.rank === "mod";
        state.isT1     = msg.payload.rank === "t1";
        if (adminSidebarEl) adminSidebarEl.hidden = !(state.isAdmin || state.isMod);
        if (memberSidebarEl) memberSidebarEl.hidden = false;
        syncRoleSettingOnRadio();
        if (rosterBtnWrapEl) rosterBtnWrapEl.hidden = !(state.isAdmin || state.isMod);
        if (serverAdminTabBtnEl) {
          const canAdmin = state.isAdmin || state.isMod;
          serverAdminTabBtnEl.hidden = !canAdmin;
          serverAdminTabBtnEl.classList.toggle("active", canAdmin && adminSidebarEl && !adminSidebarEl.hidden);
        }
        if (adminPageBtn) {
          adminPageBtn.hidden = !(state.isAdmin || state.isMod);
        }
        if (state.isT1) {
          pttBtn.disabled = true;
          pttBtn.title = 'Ask an admin to assign you a higher rank to transmit';
          setStatus('Rank updated: T1 (no TX)');
        } else {
          pttBtn.disabled = false;
          pttBtn.title = '';
          setStatus(`Rank updated: ${RANK_LABELS[msg.payload.rank] || msg.payload.rank}`);
        }
        if (adminSidebarEl && !adminSidebarEl.hidden) loadAdminMembers();
      }
      if (adminSidebarEl && !adminSidebarEl.hidden) loadAdminMembers();
      return;
    }

    if (msg.type === "channels-updated") {
      if (Array.isArray(msg.payload.channels)) {
        state.availableChannels = msg.payload.channels;
        // Check if current channel is still allowed
        const stillAllowed = state.availableChannels.find(ch => ch.id === state.selectedChannel && ch.allowed);
        if (!stillAllowed) {
          // Switch to first allowed channel
          const firstAllowed = state.availableChannels.find(ch => ch.allowed);
          if (firstAllowed) {
            state.selectedChannel = firstAllowed.id;
            updateChannelDisplay();
          }
        }
        updateMenuDisplay();
        refreshPeerList();
      }
      return;
    }
  };
}

if (roleEl) roleEl.addEventListener("change", () => {
  updateMenuDisplay();
  updatePresence();
});
trainIdEl.addEventListener("input", () => {
  // Filter to only numeric characters
  trainIdEl.value = trainIdEl.value.replace(/[^0-9]/g, "");
});

trainIdEl.addEventListener("change", () => {
  updateChannelDisplay();
  updateMenuDisplay();
  updatePresence();
});

function muteAllPeers(muted) {
  for (const peer of state.peers.values()) {
    if (peer.peerGainNode) {
      peer.peerGainNode.gain.value = muted ? 0 : state.rxVolume;
    }
    // Unmuting is left to routePeerAudio so a silent peer stays silent.
    if (muted && peer.relayCleanGain) {
      peer.relayCleanGain.gain.value = 0;
    }
    if (peer.audio) {
      peer.audio.muted = muted || !state.cleanMonitorEnabled;
      peer.audio.volume = muted ? 0 : state.rxVolume;
    }
  }
}

function pttDown() {
  if (state.powerMode !== "on") {
    return;
  }

  if (state.isT1) {
    setStatus('T1 rank cannot transmit. Ask an admin to assign you a higher rank.');
    return;
  }

  if (state.isPttPressed) {
    return;
  }

  state.isPttPressed = true;
  initAudioEngine();
  unlockRemoteAudio();
  muteAllPeers(true);
  syncBlockingTone();
  playPttClick(true);
  wsSend("ptt-request", { channel: state.selectedChannel || DEFAULT_CHANNEL });
}

function pttUp() {
  if (!state.isPttPressed) {
    return;
  }

  state.isPttPressed = false;
  wsSend("ptt-release", {});
  playRogerBeep();
  playPttClick(false);
  cutNoiseNow();
  applyCurrentMonitorRouting();
  syncBlockingTone();
}

function forcePttRelease() {
  if (!state.isPttPressed) {
    return;
  }

  pttUp();
}

// Room management functions
async function loadRoomsList() {
  if (!roomListEl) return;

  roomListEl.innerHTML = '<div class="loading">Loading servers...</div>';

  try {
    const response = await fetch(withAuthQuery("/api/rooms"), {
      method: "GET",
      cache: "no-store"
    });

    if (!response.ok) {
      roomListEl.innerHTML = '<div class="error">Failed to load servers</div>';
      return;
    }

    const data = await response.json();
    const rooms = data.rooms || [];

    if (rooms.length === 0) {
      roomListEl.innerHTML = '<div class="empty-state">No servers available. Create one!</div>';
      return;
    }

    roomListEl.innerHTML = rooms.map(room => `
      <div class="room-card">
        <div class="room-header">
          <h3>${escapeHtml(room.name || 'Untitled Server')}</h3>
        </div>
        <div class="room-info">
          <div class="room-users-label"><strong>${room.memberCount}</strong> user${room.memberCount !== 1 ? 's' : ''} online:</div>
          ${room.members && room.members.length > 0 ? `<div class="room-members">${room.members.map(m => escapeHtml(m.name)).join(', ')}</div>` : '<div class="room-members"><em>None</em></div>'}
        </div>
        <button class="btn-join-room" data-room-id="${escapeHtml(room.id)}">
          Join
        </button>
      </div>
    `).join('');

    // Add event listeners to join buttons
    document.querySelectorAll('.btn-join-room').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        const roomId = btn.dataset.roomId;
        const userName = currentUsername || generateRoomUserName();
        joinRoom(roomId, userName);
      });
    });
  } catch (err) {
    roomListEl.innerHTML = '<div class="error">Error loading servers</div>';
  }
}

function generateRoomUserName() {
  const names = ['Operator', 'Dispatcher', 'Control'];
  return `${names[Math.floor(Math.random() * names.length)]}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`;
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

async function joinRoom(roomId, userName) {
  state.currentRoom = roomId;

  if (!state.ws || state.ws.readyState !== WebSocket.OPEN) {
    await join(roomId, userName);
    return;
  }

  // If already connected, send join message
  wsSend("join", {
    roomId,
    userName,
    role: roleEl.value,
    trainId: trainIdEl.value,
    transport: "webrtc"
  });

  if (roomSelectionModalEl) {
    roomSelectionModalEl.classList.remove('active');
  }
}

function showRoomTab(tabName) {
  // Hide all tabs
  document.querySelectorAll('.modal-tab-content').forEach(el => {
    el.classList.remove('active');
    el.hidden = true;
  });

  // Remove active class from all buttons
  document.querySelectorAll('.modal-tab').forEach(btn => {
    btn.classList.remove('active');
  });

  // Show selected tab
  const tabEl = document.getElementById(tabName);
  if (tabEl) {
    tabEl.classList.add('active');
    tabEl.hidden = false;
  }

  // Mark button as active
  if (tabName === 'join-room' && joinRoomTabEl) {
    joinRoomTabEl.classList.add('active');
    loadRoomsList();
  } else if (tabName === 'create-room' && createRoomTabEl) {
    createRoomTabEl.classList.add('active');
  }
}

function roleBadge(rank) {
  const label = RANK_LABELS[rank] || rank;
  return `<span class="role-badge role-badge--${escapeHtml(rank)}">${escapeHtml(label)}</span>`;
}

async function loadAdminMembers() {
  if (!state.currentRoom || !adminMembersListEl) return;

  adminMembersListEl.innerHTML = '<div class="loading">Loading...</div>';

  try {
    const membersRes = await fetch(withAuthQuery(`/api/rooms/${state.currentRoom}/members`), { method: "GET", cache: "no-store" });

    if (!membersRes.ok) {
      adminMembersListEl.innerHTML = '<div class="error">Failed to load members</div>';
      return;
    }

    const { members = [] } = await membersRes.json();
    adminMembersListEl.innerHTML = members.length === 0
      ? '<div class="empty-state">No one online</div>'
      : members.map(member => {
          const isStaff = state.isAdmin || state.isMod;
          const isSelf = member.id === state.selfId;
          const isCreator = member.id === state.currentCreatorId;
          // Session roles the member is allowed based on their rank
          const memberAllowed = allowedSessionRoles(member.rank || "t1");
          return `
          <div class="member-item">
            <div class="member-info">
              <div class="member-name">${escapeHtml(member.name)}${isSelf ? ' <small>(You)</small>' : ''}</div>
              ${roleBadge(member.rank || "t1")}
            </div>
            <div class="member-actions">
              ${isStaff && !isSelf && !isCreator ? `
                <select class="member-role-select" data-member-id="${escapeHtml(member.id)}">
                  ${memberAllowed.map(r =>
                    `<option value="${r}" ${member.role === r ? 'selected' : ''}>${SESSION_LABELS[r] || r}</option>`
                  ).join('')}
                </select>
                <button class="btn-kick" data-member-id="${escapeHtml(member.id)}">Kick</button>
              ` : isCreator && !isSelf ? '<small>Creator</small>' : ''}
            </div>
          </div>`;
        }).join('');

    adminMembersListEl.querySelectorAll('.member-role-select').forEach(select => {
      select.addEventListener('change', async (e) => {
        const memberId = e.target.dataset.memberId;
        const newSessionRole = e.target.value;
        try {
          const r = await fetch(withAuthQuery(`/api/rooms/${state.currentRoom}/members/${memberId}/role`), {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ role: newSessionRole })
          });
          if (!r.ok) { setStatus('Failed to update role'); loadAdminMembers(); return; }
          setStatus('Session role updated');
        } catch { setStatus('Error updating role'); }
      });
    });

    adminMembersListEl.querySelectorAll('.btn-kick').forEach(btn => {
      btn.addEventListener('click', async () => {
        const memberId = btn.dataset.memberId;
        if (!confirm('Kick this user?')) return;
        try {
          const r = await fetch(withAuthQuery(`/api/rooms/${state.currentRoom}/members/${memberId}/kick`), {
            method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({})
          });
          if (!r.ok) { setStatus('Failed to kick user'); return; }
          setStatus('User kicked');
          loadAdminMembers();
        } catch { setStatus('Error kicking user'); }
      });
    });
  } catch (err) {
    adminMembersListEl.innerHTML = '<div class="error">Error loading members</div>';
  }
}

async function loadRosterModal() {
  if (!state.currentRoom || !rosterModalListEl) return;

  rosterModalListEl.innerHTML = '<div class="loading">Loading...</div>';

  try {
    const res = await fetch(withAuthQuery(`/api/rooms/${state.currentRoom}/roster`), { method: "GET", cache: "no-store" });
    if (!res.ok) {
      rosterModalListEl.innerHTML = '<div class="error">Failed to load roster</div>';
      return;
    }

    const { roster = [] } = await res.json();
    rosterModalListEl.innerHTML = roster.length === 0
      ? '<div class="empty-state">No saved roles yet</div>'
      : roster.map(entry => `
          <div class="member-item ${entry.online ? 'roster-online' : 'roster-offline'}">
            <div class="member-info">
              <div class="member-name">
                <span class="roster-dot" title="${entry.online ? 'Online' : 'Offline'}"></span>
                ${escapeHtml(entry.username)}
              </div>
              ${roleBadge(entry.rank || "t1")}
            </div>
            <div class="member-actions">
              ${entry.userId === currentUserId ? '<small>You</small>' : `
                <select class="roster-role-select" data-user-id="${escapeHtml(entry.userId)}">
                  <option value="t1" ${entry.rank === 't1' ? 'selected' : ''}>T1</option>
                  <option value="t2" ${entry.rank === 't2' ? 'selected' : ''}>T2</option>
                  <option value="t3" ${entry.rank === 't3' ? 'selected' : ''}>T3</option>
                  ${state.isAdmin ? `<option value="mod" ${entry.rank === 'mod' ? 'selected' : ''}>Moderator</option>` : ''}
                </select>
              `}
            </div>
          </div>
        `).join('');

    rosterModalListEl.querySelectorAll('.roster-role-select').forEach(select => {
      select.addEventListener('change', async (e) => {
        const userId = e.target.dataset.userId;
        const newRank = e.target.value;
        try {
          const r = await fetch(withAuthQuery(`/api/rooms/${state.currentRoom}/roster/${userId}/role`), {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ role: newRank })
          });
          if (!r.ok) { setStatus('Failed to update rank'); loadRosterModal(); return; }
          setStatus('Rank updated');
          loadRosterModal();
        } catch { setStatus('Error updating rank'); }
      });
    });
  } catch (err) {
    rosterModalListEl.innerHTML = '<div class="error">Error loading roster</div>';
  }
}

async function loadServerEditorModal() {
  if (!serverEditorListEl) return;

  serverEditorListEl.innerHTML = '<div class="loading">Loading servers...</div>';

  try {
    const res = await fetch(withAuthQuery('/api/rooms'), { method: 'GET', cache: 'no-store' });
    if (!res.ok) {
      serverEditorListEl.innerHTML = '<div class="error">Failed to load servers</div>';
      return;
    }

    const data = await res.json();
    const rooms = Array.isArray(data.rooms) ? data.rooms : [];
    if (rooms.length === 0) {
      serverEditorListEl.innerHTML = '<div class="empty-state">No servers found</div>';
      return;
    }

    serverEditorListEl.innerHTML = rooms.map(room => `
      <div class="member-item server-editor-item">
        <div class="member-info">
          <div class="member-name">${escapeHtml(room.name || 'Untitled Server')}</div>
          <div class="member-role">ID: ${escapeHtml(room.id || '')}</div>
        </div>
        <div class="member-actions server-editor-actions">
          <input class="server-name-input" data-room-id="${escapeHtml(room.id || '')}" type="text" value="${escapeHtml(room.name || '')}" maxlength="80" />
          <button class="admin-sidebar-btn btn-rename-server" data-room-id="${escapeHtml(room.id || '')}" type="button">Rename</button>
          <button class="btn-kick btn-delete-server" data-room-id="${escapeHtml(room.id || '')}" type="button">Delete</button>
        </div>
      </div>
    `).join('');

    serverEditorListEl.querySelectorAll('.btn-rename-server').forEach(btn => {
      btn.addEventListener('click', async () => {
        const roomId = btn.dataset.roomId;
        const input = serverEditorListEl.querySelector(`.server-name-input[data-room-id="${roomId}"]`);
        const nextName = input ? input.value.trim() : '';
        if (!nextName) {
          setStatus('Server name cannot be empty');
          return;
        }

        try {
          const r = await fetch(withAuthQuery(`/api/rooms/${roomId}`), {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: nextName })
          });
          if (!r.ok) {
            const err = await r.json().catch(() => ({}));
            setStatus(err.error || 'Failed to rename server');
            return;
          }

          if (state.currentRoom === roomId) {
            state.currentRoomName = nextName;
            if (serverNameEl) serverNameEl.textContent = nextName;
          }
          setStatus('Server renamed');
          loadServerEditorModal();
          loadRoomsList();
        } catch (_err) {
          setStatus('Error renaming server');
        }
      });
    });

    serverEditorListEl.querySelectorAll('.btn-delete-server').forEach(btn => {
      btn.addEventListener('click', async () => {
        const roomId = btn.dataset.roomId;
        if (!confirm('Delete this server? All connected users will be disconnected.')) return;

        try {
          const r = await fetch(withAuthQuery(`/api/rooms/${roomId}`), { method: 'DELETE' });
          if (!r.ok) {
            const err = await r.json().catch(() => ({}));
            setStatus(err.error || 'Failed to delete server');
            return;
          }
          setStatus('Server deleted');
          loadServerEditorModal();
          loadRoomsList();
        } catch (_err) {
          setStatus('Error deleting server');
        }
      });
    });
  } catch (_err) {
    serverEditorListEl.innerHTML = '<div class="error">Error loading servers</div>';
  }
}

// Roster modal open/close
if (openRosterBtnEl) {
  openRosterBtnEl.addEventListener('click', () => {
    if (rosterModalEl) {
      rosterModalEl.hidden = false;
      loadRosterModal();
    }
  });
}
if (closeRosterBtnEl) {
  closeRosterBtnEl.addEventListener('click', () => {
    if (rosterModalEl) rosterModalEl.hidden = true;
  });
}
// Close on backdrop click
if (rosterModalEl) {
  rosterModalEl.addEventListener('click', (e) => {
    if (e.target === rosterModalEl) rosterModalEl.hidden = true;
  });
}

if (openServerEditorBtnEl) {
  openServerEditorBtnEl.addEventListener('click', () => {
    if (serverEditorModalEl) {
      serverEditorModalEl.hidden = false;
      loadServerEditorModal();
    }
  });
}

if (closeServerEditorBtnEl) {
  closeServerEditorBtnEl.addEventListener('click', () => {
    if (serverEditorModalEl) serverEditorModalEl.hidden = true;
  });
}

if (serverEditorModalEl) {
  serverEditorModalEl.addEventListener('click', (e) => {
    if (e.target === serverEditorModalEl) serverEditorModalEl.hidden = true;
  });
}

joinBtn.addEventListener("click", () => {
  if (state.ws && (state.ws.readyState === WebSocket.OPEN || state.ws.readyState === WebSocket.CONNECTING)) {
    setStatus("Disconnecting...");
    state.ws.close();
    return;
  }

  // Show room selection modal
  if (roomSelectionModalEl) {
    roomSelectionModalEl.classList.add('active');
    showRoomTab('join-room');
  } else {
    join().catch((err) => {
      setPowerState("off");
      setStatus(`Join failed: ${err.message}`);
    });
  }
});

if (opsTabBtnEl) {
  opsTabBtnEl.addEventListener("click", () => {
    showTab(opsTabBtnEl, opsPanelEl);
  });
}

if (serverAdminTabBtnEl) {
  serverAdminTabBtnEl.addEventListener("click", () => {
    const canAdmin = state.isAdmin || state.isMod;
    if (!canAdmin || !adminSidebarEl) return;

    adminSidebarEl.hidden = !adminSidebarEl.hidden;
    serverAdminTabBtnEl.classList.toggle("active", !adminSidebarEl.hidden);

    if (!adminSidebarEl.hidden) {
      loadAdminMembers();
    }
  });
}

if (settingsTabBtnEl) {
  settingsTabBtnEl.addEventListener("click", () => {
    showTab(settingsTabBtnEl, settingsPanelEl);
  });
}

// D-pad navigation for menu system
const channelUpBtn = document.querySelector(".apx-dpad-up");
const channelDownBtn = document.querySelector(".apx-dpad-dn");
const navLeftBtn = document.getElementById("navLeftBtn");
const navRightBtn = document.getElementById("navRightBtn");
const dpadOkBtn = document.querySelector(".apx-dpad-ok");

if (channelUpBtn) {
  channelUpBtn.addEventListener("click", () => menuStepItem(-1));
}

if (channelDownBtn) {
  channelDownBtn.addEventListener("click", () => menuStepItem(1));
}

if (navLeftBtn) {
  navLeftBtn.addEventListener("click", () => menuChangeCurrentItem(-1));
}

if (navRightBtn) {
  navRightBtn.addEventListener("click", () => menuChangeCurrentItem(1));
}

if (dpadOkBtn) {
  dpadOkBtn.addEventListener("click", menuConfirmSelection);
}

// Number keypad handlers for train ID editing
const keypadKeys = document.querySelectorAll(".apx-key");
const keypadStarBtn = document.querySelector(".apx-key-star");
const keypadHashBtn = document.querySelector(".apx-key-hash");

keypadKeys.forEach(btn => {
  btn.addEventListener("click", () => {
    const digit = btn.textContent.charAt(0);
    if (/\d/.test(digit)) {
      menuNumberKeypad(digit);
    }
  });
});

if (keypadStarBtn) {
  keypadStarBtn.addEventListener("click", () => {
    // Star button = Backspace (delete last character)
    if (state.menuState.selectedItem === 2 && state.menuState.editMode) {
      state.menuState.trainIdEditValue = state.menuState.trainIdEditValue.slice(0, -1);
      if (menuTrainIdEl) {
        menuTrainIdEl.textContent = state.menuState.trainIdEditValue || "----";
      }
    }
  });
}

if (keypadHashBtn) {
  keypadHashBtn.addEventListener("click", () => {
    // CLR button clears all train ID digits
    if (state.menuState.selectedItem === 2 && state.menuState.editMode) {
      state.menuState.trainIdEditValue = "";
      if (menuTrainIdEl) {
        menuTrainIdEl.textContent = "----";
      }
    }
  });
}

pttBtn.addEventListener("mousedown", pttDown);
pttBtn.addEventListener("mouseup", pttUp);
pttBtn.addEventListener("mouseleave", pttUp);
pttBtn.addEventListener("touchstart", (event) => {
  event.preventDefault();
  pttDown();
}, { passive: false });
pttBtn.addEventListener("touchend", (event) => {
  event.preventDefault();
  pttUp();
}, { passive: false });
pttBtn.addEventListener("touchcancel", pttUp, { passive: true });
pttBtn.addEventListener("pointerdown", pttDown);
pttBtn.addEventListener("pointerup", pttUp);
pttBtn.addEventListener("pointercancel", pttUp);

window.addEventListener("keydown", (event) => {
  if (event.code === state.pttKeyCode) {
    if (event.repeat) {
      return;
    }
    event.preventDefault();
    initAudioEngine();
    pttDown();
  }
});

window.addEventListener("keyup", (event) => {
  if (event.code === state.pttKeyCode) {
    event.preventDefault();
    pttUp();
  }
});

window.addEventListener("pointerdown", () => {
  initAudioEngine();
  unlockRemoteAudio();
});

window.addEventListener("visibilitychange", () => {
  if (document.visibilityState !== "visible") {
    forcePttRelease();
  }
});

window.addEventListener("blur", () => {
  forcePttRelease();
});

loadSettings();
state.selectedChannel = DEFAULT_CHANNEL;
updateChannelDisplay();
updateMenuDisplay();
updateMenuItemHighlight();
state.rxVolume = state.masterVolume;
setupKnobControl(volKnobEl, "masterVolume");
applyVolumeState();

if (cleanCheckBtn) {
  cleanCheckBtn.addEventListener("click", () => {
    state.cleanMonitorEnabled = !state.cleanMonitorEnabled;
    updateCleanCheckButton();
    applyCurrentMonitorRouting();
    setStatus(state.cleanMonitorEnabled ? "Audio filter bypassed" : "Audio filter enabled");
  });
}

if (opsTabBtnEl && settingsTabBtnEl) {
  opsTabBtnEl.addEventListener("click", () => setActiveTab("ops"));
  settingsTabBtnEl.addEventListener("click", async () => {
    setActiveTab("settings");
    await populateDeviceSelectors();
  });
}

function friendlyKeyName(code) {
  const map = {
    Space: "Space", Enter: "Enter", Escape: "Escape", Tab: "Tab",
    Backspace: "Backspace", Delete: "Delete",
    ShiftLeft: "Left Shift", ShiftRight: "Right Shift",
    ControlLeft: "Left Ctrl", ControlRight: "Right Ctrl",
    AltLeft: "Left Alt", AltRight: "Right Alt",
    MetaLeft: "Left Win", MetaRight: "Right Win",
    ArrowUp: "↑", ArrowDown: "↓", ArrowLeft: "←", ArrowRight: "→",
  };
  if (map[code]) return map[code];
  // KeyA → A, Digit1 → 1, Numpad0 → Num0, F1 → F1
  if (/^Key[A-Z]$/.test(code)) return code.slice(3);
  if (/^Digit\d$/.test(code)) return code.slice(5);
  if (/^Numpad(.+)$/.test(code)) return "Num" + code.slice(6);
  return code;
}

if (pttKeyCaptureEl) {
  pttKeyCaptureEl.textContent = friendlyKeyName(state.pttKeyCode);

  pttKeyCaptureEl.addEventListener("click", () => {
    if (pttKeyCaptureEl.classList.contains("capturing")) return;
    pttKeyCaptureEl.classList.add("capturing");
    pttKeyCaptureEl.textContent = "Press a key…";

    function onCapture(e) {
      e.preventDefault();
      e.stopPropagation();
      // Ignore bare modifier-only presses so user can combine
      if (["Shift", "Control", "Alt", "Meta"].includes(e.key)) return;
      state.pttKeyCode = e.code;
      saveSettings();
      pttKeyCaptureEl.classList.remove("capturing");
      pttKeyCaptureEl.textContent = friendlyKeyName(e.code);
      setStatus(`PTT key set to ${friendlyKeyName(e.code)}`);
      window.removeEventListener("keydown", onCapture, true);
    }
    window.addEventListener("keydown", onCapture, true);
  });
}

if (micSelectEl) {
  micSelectEl.addEventListener("change", async () => {
    await switchMicrophone(micSelectEl.value || "");
    updateMenuDisplay();
  });
}

if (outputSelectEl) {
  outputSelectEl.addEventListener("change", async () => {
    state.selectedOutputDeviceId = outputSelectEl.value || "";
    saveSettings();
    await applyOutputDeviceToPeers();
    setStatus("Audio output updated");
    updateMenuDisplay();
  });
}

if (navigator.mediaDevices && typeof navigator.mediaDevices.addEventListener === "function") {
  navigator.mediaDevices.addEventListener("devicechange", () => {
    populateDeviceSelectors();
  });
}

// Room management event listeners
if (joinRoomTabEl) {
  joinRoomTabEl.addEventListener('click', () => showRoomTab('join-room'));
}

if (createRoomTabEl) {
  createRoomTabEl.addEventListener('click', () => showRoomTab('create-room'));
}

if (createRoomFormEl) {
  createRoomFormEl.addEventListener('submit', async (e) => {
    e.preventDefault();
    const roomName = newRoomNameEl.value.trim();
    // Use logged-in username as display name
    const userName = currentUsername || generateRoomUserName();

    createRoomErrorEl.textContent = '';

    try {
      const response = await fetch(withAuthQuery('/api/rooms'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ roomName })
      });

      if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        createRoomErrorEl.textContent = error.error || 'Failed to create server';
        return;
      }

      const data = await response.json();
      state.currentCreatorId = data.creatorId;
      const createdRoomId = data && data.room ? data.room.id : null;
      if (!createdRoomId) {
        createRoomErrorEl.textContent = 'Server created but room id missing';
        return;
      }

      // Join the newly created room
      await joinRoom(createdRoomId, userName);
    } catch (err) {
      createRoomErrorEl.textContent = 'Error creating server';
    }
  });
}

if (adminPageBtn) {
  adminPageBtn.addEventListener("click", () => {
    window.location.href = "/admin.html";
  });
}

if (roomSelectionModalEl) {
  // Close modal when clicking outside
  roomSelectionModalEl.addEventListener('click', (e) => {
    if (e.target === roomSelectionModalEl) {
      roomSelectionModalEl.classList.remove('active');
    }
  });
}

setActiveTab("ops");
populateDeviceSelectors();

// Initialize: check auth and populate user info
(async () => {
  const authed = await ensureAuthenticated();
  if (!authed) return;

  const loggedInUserEl = document.getElementById("loggedInUser");
  if (loggedInUserEl && currentUsername) {
    loggedInUserEl.textContent = currentUsername;
  }

  const logoutBtnEl = document.getElementById("logoutBtn");
  if (logoutBtnEl) {
    logoutBtnEl.addEventListener("click", async () => {
      await fetch("/auth/logout", { method: "POST" });
      window.location.href = "/login";
    });
  }

  // Preload room list for when modal opens
  loadRoomsList().catch(() => {});
})();

updateCleanCheckButton();
setPowerState("off");

setServerStatus("Server: checking...");
setUserStatus("User: offline");
startServerStatusProbe();

// ── Viewport fit: scale the radio to fill the screen without scroll ──
(function initViewportFit() {
  const wrapper = document.querySelector(".apx-wrapper");
  const titlePanel = document.querySelector(".title-panel");
  if (!wrapper) return;

  function fit() {
    // Reset to natural size so we can measure
    wrapper.style.zoom = "1";
    const naturalW = wrapper.offsetWidth;
    const naturalH = wrapper.offsetHeight;

    const titleH = titlePanel ? titlePanel.offsetHeight : 0;
    const shellPad = 10; // top padding + gap
    const availW = window.innerWidth * 0.97;
    const availH = window.innerHeight - titleH - shellPad;

    const scale = Math.min(availW / naturalW, availH / naturalH, 1);
    wrapper.style.zoom = String(Math.max(0.25, scale).toFixed(4));
  }

  window.addEventListener("resize", fit);
  if (document.readyState === "complete") {
    fit();
  } else {
    window.addEventListener("load", fit);
  }
})();
