<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { save, open } from "@tauri-apps/plugin-dialog";

  interface ProcessInfo {
    pid: number;
    name: string;
    path: string | null;
    attachable: boolean;
  }

  interface ProcessListResponse {
    processes: ProcessInfo[];
    total: number;
  }

  interface AttachResult {
    pid: number;
    name: string;
    arch: string;
  }

  interface RegionInfo {
    start: string;
    end: string;
    size: number;
    readable: boolean;
    writable: boolean;
    executable: boolean;
    module: string | null;
  }

  interface RegionsResponse {
    regions: RegionInfo[];
    total: number;
    page: number;
    per_page: number;
  }

  interface ScanResult {
    address: string;
    value: string;
  }

  interface WatchInfo {
    id: string;
    address: string;
    value_type: string;
    label: string;
    value: string | null;
    frozen: boolean;
    freeze_value: string | null;
  }

  interface ProjectInfo {
    name: string;
    path: string | null;
    watch_count: number;
    has_unsaved_changes: boolean;
  }

  interface ScriptRunResult {
    run_id: string;
  }

  interface ScriptOutputResult {
    lines: string[];
    finished: boolean;
    error: string | null;
  }

  interface PatternScanResult {
    address: string;
    module: string | null;
    module_offset: string | null;
  }

  interface SignatureInfo {
    id: string;
    label: string;
    pattern: string;
    module: string;
    offset: number;
    value_type: string;
    resolved_address: string | null;
  }

  // State
  let processes: ProcessInfo[] = $state.raw([]);
  let loading = $state(false);
  let error: string | null = $state(null);
  let filter = $state("");
  let showOnlyAttachable = $state(false);  // Default to showing all processes
  let attachedProcess: AttachResult | null = $state(null);

  // Filtered processes based on search and attachable filter
  const filteredProcesses = $derived.by(() => {
    let result = processes;

    // Filter by attachable
    if (showOnlyAttachable) {
      result = result.filter(p => p.attachable);
    }

    // Filter by search text
    if (filter.trim()) {
      const searchLower = filter.toLowerCase();
      result = result.filter(p =>
        p.name.toLowerCase().includes(searchLower) ||
        p.pid.toString().includes(filter)
      );
    }

    return result;
  });
  let selectedPid: number | null = $state(null);
  let processDisplayLimit = $state(50);  // Limit displayed processes for performance
  const PROCESS_DISPLAY_INCREMENT = 50;

  // Tabs
  let activeTab = $state<"scan" | "watch" | "regions" | "patterns">("scan");

  // Console panel
  let consoleOpen = $state(false);
  let consoleHeight = $state(250);
  let isResizingConsole = $state(false);
  let consoleOutputEl: HTMLElement | null = $state(null);
  let showScriptHelp = $state(false);

  // Regions
  let regions: RegionInfo[] = $state.raw([]);
  let totalRegions = $state(0);
  let loadingRegions = $state(false);
  let regionSortBy = $state<"address" | "size" | "module" | "perms">("address");
  let regionSortAsc = $state(true);
  let regionShowAll = $state(false);
  let regionModuleFilter = $state("");
  let regionPage = $state(0);
  const REGIONS_PER_PAGE = 100;

  // Memory Viewer
  let memoryViewerOpen = $state(false);
  let memoryViewerAddress = $state("");
  let memoryViewerBytes: number[] = $state([]);
  let memoryViewerLoading = $state(false);
  let memoryViewerRegion: RegionInfo | null = $state(null);
  let memoryViewerOffset = $state(0);
  const BYTES_PER_PAGE = 256; // 16 rows of 16 bytes

  // Scan
  let scanValueType = $state("i32");
  let scanValue = $state("");
  let stringMaxLen = $state(256); // Max length for string scans
  // Compute effective value type (handles string[N] format)
  let effectiveValueType = $derived(
    scanValueType === "string" ? `string[${stringMaxLen}]` : scanValueType
  );
  let scanResults: ScanResult[] = $state.raw([]);
  let scanning = $state(false);
  let totalScanResults = $state(0);
  let hasPreviousScan = $state(false);
  let refineMode = $state("exact");

  // Watch
  let watches: WatchInfo[] = $state([]);
  let loadingWatches = $state(false);
  let watchPollInterval: number | null = $state(null);
  // Manual entry
  let showManualEntry = $state(false);
  let manualAddress = $state("");
  let manualValueType = $state("i32");
  let manualStringMaxLen = $state(256); // Max length for manual string watches
  let manualLabel = $state("");
  // Compute effective manual value type
  let effectiveManualValueType = $derived(
    manualValueType === "string" ? `string[${manualStringMaxLen}]` : manualValueType
  );
  // Inline editing
  let editingWatchId: string | null = $state(null);
  let editingWatchValue = $state("");
  let editingWatchLabel = $state("");

  // Project
  let projectInfo: ProjectInfo = $state({ name: "Untitled", path: null, watch_count: 0, has_unsaved_changes: false });
  let showProjectMenu = $state(false);
  let editingProjectName = $state(false);
  let projectNameInput = $state("");

  // Prompt dialog (for new project, etc.)
  let promptDialog: { title: string; placeholder: string; value: string; onConfirm: (value: string) => void } | null = $state(null);

  // Guided Scan Wizard
  let wizardMode = $state(false);
  let wizardStep = $state(1);
  let wizardValueName = $state(""); // e.g., "Health", "Ammo", "Money"
  let wizardHistory: string[] = $state([]); // Track what user did

  // Script tabs
  interface ScriptTab {
    id: string;
    name: string;
    source: string;
    output: string[];
    runId: string | null;
    running: boolean;
    dirty: boolean; // Has unsaved changes
    savedId: string | null; // ID in project, null if never saved
  }

  interface SavedScript {
    id: string;
    name: string;
    source: string;
    enabled: boolean;
  }

  const DEFAULT_SCRIPT = `// Messpit Script
// Available API: mem.read, mem.write, watch.add, freeze.set, ui.notify, time.sleep

// Example: Read and print a value
// const value = mem.read(0x12345678, "i32");
// ui.print("Value: " + value);
`;

  function createNewTab(name: string = "Untitled", source: string = DEFAULT_SCRIPT): ScriptTab {
    return {
      id: crypto.randomUUID(),
      name,
      source,
      output: [],
      runId: null,
      running: false,
      dirty: false,
      savedId: null,
    };
  }

  const initialTab = createNewTab();
  let scriptTabs: ScriptTab[] = $state([initialTab]);
  let activeTabId: string = $state(initialTab.id);
  let savedScripts: SavedScript[] = $state.raw([]);
  let showScriptMenu = $state(false);
  let editingTabName: string | null = $state(null);
  let editingTabNameValue = $state("");
  let scriptApiTypes = $state("");

  // Derived: get active tab
  function getActiveTab(): ScriptTab | undefined {
    return scriptTabs.find(t => t.id === activeTabId);
  }

  // Legacy compatibility - will be refactored
  let scriptRunning = $derived(getActiveTab()?.running ?? false);
  let scriptRunId = $derived(getActiveTab()?.runId ?? null);
  let scriptOutput = $derived(getActiveTab()?.output ?? []);
  let scriptSource = $derived(getActiveTab()?.source ?? "");

  // Pattern scanning
  let patternInput = $state("");
  let patternModule = $state("");
  let patternResults: PatternScanResult[] = $state([]);
  let patternScanning = $state(false);
  let signatures: SignatureInfo[] = $state([]);
  let showAddSignature = $state(false);
  let newSigLabel = $state("");
  let newSigPattern = $state("");
  let newSigModule = $state("");
  let newSigOffset = $state("0");
  let newSigValueType = $state("i32");

  // Toast notifications
  interface Toast {
    id: number;
    message: string;
    type: "success" | "error" | "info";
  }
  let toasts: Toast[] = $state([]);
  let toastId = 0;

  function showToast(message: string, type: "success" | "error" | "info" = "success") {
    const id = ++toastId;
    toasts = [...toasts, { id, message, type }];
    setTimeout(() => {
      toasts = toasts.filter(t => t.id !== id);
    }, 3000);
  }

  // Pinned processes - use Set for O(1) lookups
  let pinnedPids: Set<number> = $state(new Set());

  function togglePinProcess(pid: number) {
    const newPinned = new Set(pinnedPids);
    if (newPinned.has(pid)) {
      newPinned.delete(pid);
      showToast("Process unpinned", "info");
    } else {
      newPinned.add(pid);
      showToast("Process pinned", "success");
    }
    pinnedPids = newPinned;
    // Save to localStorage
    localStorage.setItem("messpit_pinned", JSON.stringify([...pinnedPids]));
  }

  // Load pinned processes from localStorage
  function loadPinnedProcesses() {
    try {
      const saved = localStorage.getItem("messpit_pinned");
      if (saved) {
        pinnedPids = new Set(JSON.parse(saved));
      }
    } catch {}
  }

  // Value change tracking for watch list
  let previousWatchValues: Map<string, string | null> = $state(new Map());
  let changedWatchIds: Set<string> = $state(new Set());

  async function loadProcesses() {
    loading = true;
    error = null;
    try {
      processes = await invoke<ProcessInfo[]>("list_processes_cmd");
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }

  async function attachToProcess(pid: number) {
    error = null;
    try {
      // Stop polling and clear state from previous process
      stopWatchPolling();
      watches = [];
      regions = [];
      totalRegions = 0;
      scanResults = [];
      totalScanResults = 0;
      hasPreviousScan = false;

      attachedProcess = await invoke<AttachResult>("attach_process", { pid });
      selectedPid = pid;
      // Don't load regions immediately - load lazily when user switches to Regions tab
      // This prevents UI freeze for processes with many regions (like containerd/dockerd)
      startWatchPolling();
      showToast(`Attached to ${attachedProcess.name}`, "success");
    } catch (e) {
      error = String(e);
      showToast("Failed to attach to process", "error");
    }
  }

  async function detach() {
    error = null;
    try {
      stopWatchPolling();
      await invoke("detach_process");
      attachedProcess = null;
      selectedPid = null;
      regions = [];
      scanResults = [];
      hasPreviousScan = false;
      totalScanResults = 0;
    } catch (e) {
      error = String(e);
    }
  }

  async function loadRegions(page: number = 0, refresh: boolean = true) {
    // Skip if no process attached
    if (!attachedProcess) {
      return;
    }

    loadingRegions = true;
    error = null;
    if (refresh) {
      regionPage = 0;
    }
    try {
      const response = await invoke<RegionsResponse>("get_regions", {
        page,
        perPage: REGIONS_PER_PAGE,
      });
      regions = response.regions;
      totalRegions = response.total;
      regionPage = response.page;
    } catch (e) {
      error = String(e);
    } finally {
      loadingRegions = false;
    }
  }

  async function startScan() {
    if (!scanValue.trim()) {
      error = "Please enter a value to search for";
      return;
    }

    scanning = true;
    error = null;
    scanResults = [];

    try {
      scanResults = await invoke<ScanResult[]>("start_scan", {
        request: {
          value_type: effectiveValueType,
          comparison: "exact",
          value: scanValue.trim()
        }
      });
      totalScanResults = await invoke<number>("get_scan_count");
      hasPreviousScan = true;
    } catch (e) {
      error = String(e);
    } finally {
      scanning = false;
    }
  }

  async function refineScan() {
    scanning = true;
    error = null;

    try {
      scanResults = await invoke<ScanResult[]>("refine_scan", {
        request: {
          mode: refineMode,
          value: refineMode === "exact" ? scanValue.trim() || null : null
        }
      });
      totalScanResults = await invoke<number>("get_scan_count");
    } catch (e) {
      error = String(e);
    } finally {
      scanning = false;
    }
  }

  async function clearScan() {
    await invoke("clear_scan");
    scanResults = [];
    hasPreviousScan = false;
    totalScanResults = 0;
    scanValue = "";
  }

  async function addToWatch(address: string, value: string) {
    try {
      await invoke("add_watch", {
        request: {
          address,
          value_type: scanValueType,
          label: `${address.slice(-8)}`
        }
      });
      await loadWatches();
      showToast("Added to watch list", "success");
      activeTab = "watch";
    } catch (e) {
      error = String(e);
      showToast("Failed to add to watch", "error");
    }
  }

  async function loadWatches(force: boolean = false) {
    // Prevent overlapping polls - if already loading, skip this poll
    if (loadingWatches) {
      return;
    }

    // Skip polling if no attached process (unless forced)
    if (!attachedProcess && !force) {
      return;
    }

    // Skip polling if no watches exist and not forced (no point reading empty list repeatedly)
    if (watches.length === 0 && !force) {
      return;
    }

    loadingWatches = true;
    try {
      const newWatches = await invoke<WatchInfo[]>("get_watches");

      // Track value changes
      for (const watch of newWatches) {
        const prevValue = previousWatchValues.get(watch.id);
        if (prevValue !== undefined && prevValue !== watch.value) {
          // Value changed - add to changed set
          changedWatchIds = new Set([...changedWatchIds, watch.id]);
          // Remove from changed set after animation
          setTimeout(() => {
            changedWatchIds = new Set([...changedWatchIds].filter(id => id !== watch.id));
          }, 1500);
        }
        previousWatchValues.set(watch.id, watch.value);
      }

      watches = newWatches;

      // Start polling if we have watches and polling isn't running
      if (watches.length > 0 && watchPollInterval === null) {
        watchPollInterval = setInterval(loadWatches, 1000) as unknown as number;
      }
      // Stop polling if no watches
      if (watches.length === 0 && watchPollInterval !== null) {
        stopWatchPolling();
      }
    } catch (e) {
      // Silently handle watch load errors during polling
    } finally {
      loadingWatches = false;
    }
  }

  function formatProcessPath(path: string | null): string {
    if (!path) return "";
    // Get the parent directory for context
    const parts = path.split("/");
    if (parts.length <= 2) return path;
    // Show last 2-3 path components
    const name = parts.pop() || "";
    const parent = parts.pop() || "";
    const grandparent = parts.pop() || "";
    if (grandparent) {
      return `${grandparent}/${parent}`;
    }
    return parent;
  }

  async function removeWatch(id: string) {
    try {
      await invoke("remove_watch", { entryId: id });
      await loadWatches();
    } catch (e) {
      error = String(e);
    }
  }

  async function toggleFreeze(watch: WatchInfo) {
    try {
      await invoke("toggle_freeze", {
        request: {
          entry_id: watch.id,
          value: watch.value || "0"
        }
      });
      await loadWatches();
      showToast(watch.frozen ? "Value unfrozen" : "Value frozen", "info");
    } catch (e) {
      error = String(e);
      showToast("Failed to toggle freeze", "error");
    }
  }

  async function startWatchPolling() {
    stopWatchPolling();
    await loadWatches(true);  // Force initial load to check for existing watches
    // Polling is started by loadWatches when watches exist.
  }

  function stopWatchPolling() {
    if (watchPollInterval !== null) {
      clearInterval(watchPollInterval);
      watchPollInterval = null;
    }
  }

  // Manual watch entry
  async function addManualWatch() {
    if (!manualAddress.trim()) {
      error = "Please enter an address";
      return;
    }

    try {
      await invoke<string>("add_watch", {
        request: {
          address: manualAddress.trim(),
          value_type: effectiveManualValueType,
          label: manualLabel.trim() || `Manual_${manualAddress.slice(-8)}`
        }
      });
      await loadWatches();
      // Reset form
      manualAddress = "";
      manualLabel = "";
      showManualEntry = false;
    } catch (e) {
      error = String(e);
    }
  }

  // Inline editing
  function startEditingWatch(watch: WatchInfo) {
    editingWatchId = watch.id;
    editingWatchValue = watch.value || "";
    editingWatchLabel = watch.label;
  }

  function cancelEditingWatch() {
    editingWatchId = null;
    editingWatchValue = "";
    editingWatchLabel = "";
  }

  async function writeWatchValue(watch: WatchInfo) {
    if (!attachedProcess) {
      error = "No process attached - cannot write to memory";
      return;
    }

    if (!editingWatchValue.trim()) {
      error = "Please enter a value";
      return;
    }

    try {
      await invoke("write_value", {
        request: {
          address: watch.address,
          value_type: watch.value_type,
          value: editingWatchValue.trim()
        }
      });
      await loadWatches();
      cancelEditingWatch();
      showToast("Value written to memory", "success");
    } catch (e) {
      error = String(e);
      showToast("Failed to write value", "error");
    }
  }

  async function readSingleValue(address: string, valueType: string): Promise<string | null> {
    if (!attachedProcess) return null;
    try {
      return await invoke<string | null>("read_value", {
        request: { address, value_type: valueType }
      });
    } catch {
      return null;
    }
  }

  // Project management
  async function loadProjectInfo() {
    try {
      projectInfo = await invoke<ProjectInfo>("get_project_info");
    } catch (e) {
      // Ignore errors loading project info
    }
  }

  async function newProject() {
    promptDialog = {
      title: "New Project",
      placeholder: "Project name",
      value: "New Project",
      onConfirm: async (name: string) => {
        try {
          projectInfo = await invoke<ProjectInfo>("new_project", { name });
          watches = [];
          showProjectMenu = false;
        } catch (e) {
          error = String(e);
        }
      }
    };
  }

  async function saveProject() {
    try {
      let filePath = projectInfo.path;

      if (!filePath) {
        const selected = await save({
          filters: [{ name: "Messpit Project", extensions: ["messpit"] }],
          defaultPath: `${projectInfo.name}.messpit`
        });
        if (!selected) return;
        filePath = selected;
      }

      await invoke("save_project", { filePath });
      await loadProjectInfo();
      showProjectMenu = false;
    } catch (e) {
      error = String(e);
    }
  }

  async function saveProjectAs() {
    try {
      const selected = await save({
        filters: [{ name: "Messpit Project", extensions: ["messpit"] }],
        defaultPath: `${projectInfo.name}.messpit`
      });
      if (!selected) return;

      await invoke("save_project", { filePath: selected });
      await loadProjectInfo();
      showProjectMenu = false;
    } catch (e) {
      error = String(e);
    }
  }

  async function openProject() {
    try {
      const selected = await open({
        filters: [{ name: "Messpit Project", extensions: ["messpit"] }],
        multiple: false
      });
      if (!selected) return;

      projectInfo = await invoke<ProjectInfo>("load_project", { filePath: selected });
      await loadWatches();
      showProjectMenu = false;
    } catch (e) {
      error = String(e);
    }
  }

  async function exportProject() {
    try {
      const selected = await save({
        filters: [{ name: "JSON", extensions: ["json"] }],
        defaultPath: `${projectInfo.name}_export.json`
      });
      if (!selected) return;

      await invoke("export_project", { filePath: selected });
      showProjectMenu = false;
    } catch (e) {
      error = String(e);
    }
  }

  async function importProject() {
    try {
      const selected = await open({
        filters: [{ name: "JSON", extensions: ["json", "messpit"] }],
        multiple: false
      });
      if (!selected) return;

      projectInfo = await invoke<ProjectInfo>("import_project", { filePath: selected });
      await loadWatches();
      showProjectMenu = false;
    } catch (e) {
      error = String(e);
    }
  }

  function startEditingProjectName() {
    projectNameInput = projectInfo.name;
    editingProjectName = true;
  }

  async function saveProjectName() {
    if (projectNameInput.trim()) {
      await invoke("set_project_name", { name: projectNameInput.trim() });
      await loadProjectInfo();
    }
    editingProjectName = false;
  }

  // Script tab functions
  function updateActiveTab(updates: Partial<ScriptTab>) {
    scriptTabs = scriptTabs.map(t =>
      t.id === activeTabId ? { ...t, ...updates } : t
    );
  }

  function addNewTab() {
    const newTab = createNewTab();
    scriptTabs = [...scriptTabs, newTab];
    activeTabId = newTab.id;
  }

  function closeTab(tabId: string) {
    if (scriptTabs.length <= 1) return; // Keep at least one tab

    const idx = scriptTabs.findIndex(t => t.id === tabId);
    scriptTabs = scriptTabs.filter(t => t.id !== tabId);

    // If closing active tab, switch to adjacent
    if (activeTabId === tabId) {
      activeTabId = scriptTabs[Math.max(0, idx - 1)].id;
    }
  }

  function switchTab(tabId: string) {
    activeTabId = tabId;
  }

  function updateTabSource(source: string) {
    updateActiveTab({ source, dirty: true });
  }

  function startRenameTab(tabId: string) {
    const tab = scriptTabs.find(t => t.id === tabId);
    if (tab) {
      editingTabName = tabId;
      editingTabNameValue = tab.name;
    }
  }

  function finishRenameTab() {
    if (editingTabName && editingTabNameValue.trim()) {
      scriptTabs = scriptTabs.map(t =>
        t.id === editingTabName ? { ...t, name: editingTabNameValue.trim(), dirty: true } : t
      );
    }
    editingTabName = null;
    editingTabNameValue = "";
  }

  async function runScript() {
    const tab = getActiveTab();
    if (!tab || tab.running) return;

    updateActiveTab({ running: true, output: [] });
    error = null;

    try {
      const result = await invoke<ScriptRunResult>("run_script", { source: tab.source });
      updateActiveTab({ runId: result.run_id });

      // Get the output
      const output = await invoke<ScriptOutputResult>("get_script_output", { runId: result.run_id });
      updateActiveTab({ output: output.lines });
    } catch (e) {
      error = String(e);
      updateActiveTab({ output: [`Error: ${e}`] });
    } finally {
      updateActiveTab({ running: false });
    }
  }

  async function cancelScript() {
    const tab = getActiveTab();
    if (!tab?.runId) return;

    try {
      await invoke("cancel_script", { runId: tab.runId });
      updateActiveTab({ output: [...tab.output, "Script cancelled."] });
    } catch (e) {
      // Script may have already finished
    }
    updateActiveTab({ running: false });
  }

  async function loadScriptApiTypes() {
    try {
      scriptApiTypes = await invoke<string>("get_script_api_types");
    } catch (e) {
      // Ignore
    }
  }

  async function loadSavedScripts() {
    try {
      savedScripts = await invoke<SavedScript[]>("get_scripts");
    } catch (e) {
      // Ignore
    }
  }

  async function saveCurrentScript() {
    const tab = getActiveTab();
    if (!tab) return;

    try {
      const id = tab.savedId || crypto.randomUUID();
      await invoke("save_script", {
        id,
        name: tab.name,
        source: tab.source,
      });
      updateActiveTab({ savedId: id, dirty: false });
      await loadSavedScripts();
      showToast("Script saved", "success");
    } catch (e) {
      showToast(`Failed to save: ${e}`, "error");
    }
  }

  async function openSavedScript(script: SavedScript) {
    // Check if already open
    const existing = scriptTabs.find(t => t.savedId === script.id);
    if (existing) {
      activeTabId = existing.id;
      showScriptMenu = false;
      return;
    }

    // Open in new tab
    const newTab: ScriptTab = {
      id: crypto.randomUUID(),
      name: script.name,
      source: script.source,
      output: [],
      runId: null,
      running: false,
      dirty: false,
      savedId: script.id,
    };
    scriptTabs = [...scriptTabs, newTab];
    activeTabId = newTab.id;
    showScriptMenu = false;
  }

  async function deleteSavedScript(scriptId: string) {
    try {
      await invoke("delete_script", { id: scriptId });
      await loadSavedScripts();
      showToast("Script deleted", "success");
    } catch (e) {
      showToast(`Failed to delete: ${e}`, "error");
    }
  }

  async function importScriptFromFile() {
    try {
      const { open } = await import("@tauri-apps/plugin-dialog");
      const selected = await open({
        multiple: false,
        filters: [{ name: "JavaScript", extensions: ["js"] }],
      });

      if (selected) {
        const { readTextFile } = await import("@tauri-apps/plugin-fs");
        const content = await readTextFile(selected);
        const fileName = selected.split("/").pop()?.replace(".js", "") || "Imported";

        const newTab: ScriptTab = {
          id: crypto.randomUUID(),
          name: fileName,
          source: content,
          output: [],
          runId: null,
          running: false,
          dirty: true,
          savedId: null,
        };
        scriptTabs = [...scriptTabs, newTab];
        activeTabId = newTab.id;
        showToast("Script imported", "success");
      }
    } catch (e) {
      showToast(`Failed to import: ${e}`, "error");
    }
    showScriptMenu = false;
  }

  async function exportCurrentScript() {
    const tab = getActiveTab();
    if (!tab) return;

    try {
      const { save } = await import("@tauri-apps/plugin-dialog");
      const path = await save({
        defaultPath: `${tab.name}.js`,
        filters: [{ name: "JavaScript", extensions: ["js"] }],
      });

      if (path) {
        const { writeTextFile } = await import("@tauri-apps/plugin-fs");
        await writeTextFile(path, tab.source);
        showToast("Script exported", "success");
      }
    } catch (e) {
      showToast(`Failed to export: ${e}`, "error");
    }
    showScriptMenu = false;
  }

  // Pattern scanning functions
  async function runPatternScan() {
    if (!patternInput.trim()) {
      error = "Please enter a pattern";
      return;
    }

    patternScanning = true;
    error = null;

    try {
      patternResults = await invoke<PatternScanResult[]>("pattern_scan", {
        request: {
          pattern: patternInput.trim(),
          module: patternModule.trim() || null,
          use_simd: true,
        },
      });
    } catch (e) {
      error = String(e);
      patternResults = [];
    } finally {
      patternScanning = false;
    }
  }

  async function loadSignatures() {
    try {
      signatures = await invoke<SignatureInfo[]>("get_signatures");
    } catch (e) {
      error = String(e);
    }
  }

  async function addSignature() {
    if (!newSigLabel.trim() || !newSigPattern.trim() || !newSigModule.trim()) {
      error = "Please fill in all required fields";
      return;
    }

    try {
      await invoke<string>("add_signature", {
        request: {
          label: newSigLabel.trim(),
          pattern: newSigPattern.trim(),
          module: newSigModule.trim(),
          offset: parseInt(newSigOffset) || 0,
          value_type: newSigValueType,
        },
      });
      await loadSignatures();
      showAddSignature = false;
      newSigLabel = "";
      newSigPattern = "";
      newSigModule = "";
      newSigOffset = "0";
      newSigValueType = "i32";
    } catch (e) {
      error = String(e);
    }
  }

  async function removeSignature(sigId: string) {
    try {
      await invoke("remove_signature", { sigId });
      await loadSignatures();
    } catch (e) {
      error = String(e);
    }
  }

  async function watchFromSignature(sigId: string) {
    try {
      await invoke<string>("watch_from_signature", { sigId });
      await loadWatches();
      activeTab = "watch";
    } catch (e) {
      error = String(e);
    }
  }

  function promoteToSignature(result: PatternScanResult) {
    showAddSignature = true;
    newSigPattern = patternInput;
    newSigModule = result.module || "";
    newSigLabel = `Sig_${result.address.slice(-8)}`;
    newSigOffset = "0";
  }

  // Wizard functions
  function startWizard() {
    wizardMode = true;
    wizardStep = 1;
    wizardValueName = "";
    wizardHistory = [];
    hasPreviousScan = false;
    scanResults = [];
    totalScanResults = 0;
    scanValue = "";
  }

  function exitWizard() {
    wizardMode = false;
    wizardStep = 1;
  }

  async function wizardFirstScan() {
    if (!scanValue.trim()) {
      error = "Please enter the current value";
      return;
    }

    wizardHistory = [...wizardHistory, `First scan for value: ${scanValue}`];
    await startScan();

    if (totalScanResults > 0) {
      wizardStep = 2;
    }
  }

  async function wizardRefine(mode: string) {
    refineMode = mode;

    if (mode === "exact" && !scanValue.trim()) {
      error = "Please enter the new value";
      return;
    }

    const action = mode === "exact" ? `Refined to exact value: ${scanValue}` :
                   mode === "changed" ? "Refined: value changed" :
                   mode === "unchanged" ? "Refined: value unchanged" :
                   mode === "increased" ? "Refined: value increased" :
                   mode === "decreased" ? "Refined: value decreased" : `Refined: ${mode}`;

    wizardHistory = [...wizardHistory, action];
    await refineScan();

    // Check if we found it
    if (totalScanResults <= 10 && totalScanResults > 0) {
      wizardStep = 3;
    }
  }

  async function wizardAddToWatch(address: string, value: string) {
    const label = wizardValueName || address.slice(-8);
    await addToWatch(address, value);
    wizardHistory = [...wizardHistory, `Added ${label} to watch list`];
    wizardStep = 4;
  }

  function wizardReset() {
    clearScan();
    wizardStep = 1;
    wizardHistory = [];
    scanValue = "";
  }

  function formatSize(bytes: number): string {
    if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${bytes} B`;
  }

  function dismissError() {
    error = null;
  }

  // ORIGINAL: Simple init effect - load everything on startup
  $effect(() => {
    loadPinnedProcesses();
    loadProcesses();
    loadProjectInfo();
    return () => stopWatchPolling();
  });

  const writableRegions = $derived(
    regions.filter(r => r.writable && r.readable)
  );

  // Cache lowercase module filter for efficiency
  const regionModuleFilterLower = $derived(regionModuleFilter.toLowerCase());

  // Sorted and filtered regions (full list) - computed once, cached
  const filteredRegions = $derived.by(() => {
    let result = regionShowAll ? regions : regions.filter(r => r.writable);

    // Filter by module name
    if (regionModuleFilter.trim()) {
      result = result.filter(r => r.module?.toLowerCase().includes(regionModuleFilterLower));
    }

    // Sort
    return [...result].sort((a, b) => {
      let cmp = 0;
      switch (regionSortBy) {
        case "address":
          cmp = a.start.localeCompare(b.start);
          break;
        case "size":
          cmp = a.size - b.size;
          break;
        case "module":
          cmp = (a.module || "").localeCompare(b.module || "");
          break;
        case "perms":
          const permScore = (r: RegionInfo) => (r.readable ? 4 : 0) + (r.writable ? 2 : 0) + (r.executable ? 1 : 0);
          cmp = permScore(a) - permScore(b);
          break;
      }
      return regionSortAsc ? cmp : -cmp;
    });
  });

  // Total pages based on backend total (before frontend filtering)
  const regionTotalPages = $derived(Math.ceil(totalRegions / REGIONS_PER_PAGE));

  function toggleRegionSort(field: "address" | "size" | "module" | "perms") {
    if (regionSortBy === field) {
      regionSortAsc = !regionSortAsc;
    } else {
      regionSortBy = field;
      regionSortAsc = field === "address"; // Default ascending for address, descending for others
    }
  }

  function copyToClipboard(text: string) {
    navigator.clipboard.writeText(text);
    showToast("Copied to clipboard", "success");
  }

  // Memory Viewer
  async function openMemoryViewer(region: RegionInfo) {
    memoryViewerRegion = region;
    memoryViewerAddress = region.start;
    memoryViewerOffset = 0;
    memoryViewerOpen = true;
    await loadMemoryBytes();
  }

  async function loadMemoryBytes() {
    if (!memoryViewerAddress) return;
    memoryViewerLoading = true;
    try {
      // Calculate actual address with offset
      const baseAddr = parseInt(memoryViewerAddress.replace("0x", ""), 16);
      const addr = (baseAddr + memoryViewerOffset).toString(16);
      memoryViewerBytes = await invoke<number[]>("read_memory_bytes", {
        address: "0x" + addr,
        size: BYTES_PER_PAGE,
      });
    } catch (e) {
      error = String(e);
      memoryViewerBytes = [];
    } finally {
      memoryViewerLoading = false;
    }
  }

  function memoryViewerPrev() {
    if (memoryViewerOffset >= BYTES_PER_PAGE) {
      memoryViewerOffset -= BYTES_PER_PAGE;
      loadMemoryBytes();
    }
  }

  function memoryViewerNext() {
    if (memoryViewerRegion) {
      const maxOffset = memoryViewerRegion.size - BYTES_PER_PAGE;
      if (memoryViewerOffset < maxOffset) {
        memoryViewerOffset = Math.min(memoryViewerOffset + BYTES_PER_PAGE, maxOffset);
        loadMemoryBytes();
      }
    }
  }

  async function memoryViewerGoTo(addr: string) {
    const parsed = parseInt(addr.replace("0x", ""), 16);
    if (!isNaN(parsed)) {
      const baseAddr = parseInt(memoryViewerAddress.replace("0x", ""), 16);
      memoryViewerOffset = Math.max(0, parsed - baseAddr);
      await loadMemoryBytes();
    }
  }

  function formatHexByte(b: number): string {
    return b.toString(16).padStart(2, "0").toUpperCase();
  }

  function byteToAscii(b: number): string {
    // Printable ASCII range: 32-126
    return b >= 32 && b <= 126 ? String.fromCharCode(b) : ".";
  }

  function getCurrentViewAddress(): string {
    const baseAddr = parseInt(memoryViewerAddress.replace("0x", ""), 16);
    return "0x" + (baseAddr + memoryViewerOffset).toString(16).toUpperCase().padStart(16, "0");
  }

  // Console resize handlers
  function startConsoleResize(e: MouseEvent) {
    e.preventDefault();
    isResizingConsole = true;
    document.addEventListener('mousemove', handleConsoleResize);
    document.addEventListener('mouseup', stopConsoleResize);
  }

  function handleConsoleResize(e: MouseEvent) {
    if (!isResizingConsole) return;
    const mainContent = document.querySelector('.main-content');
    if (!mainContent) return;
    const rect = mainContent.getBoundingClientRect();
    const newHeight = rect.bottom - e.clientY;
    consoleHeight = Math.max(150, Math.min(newHeight, window.innerHeight * 0.7));
  }

  function stopConsoleResize() {
    isResizingConsole = false;
    document.removeEventListener('mousemove', handleConsoleResize);
    document.removeEventListener('mouseup', stopConsoleResize);
  }

  // Keyboard shortcut handler
  function handleKeydown(e: KeyboardEvent) {
    // Ctrl/Cmd + ` to toggle console
    if ((e.ctrlKey || e.metaKey) && e.key === '`') {
      e.preventDefault();
      consoleOpen = !consoleOpen;
      if (consoleOpen) { loadScriptApiTypes(); loadSavedScripts(); }
    }
    // Ctrl/Cmd+S to save current script when console is open
    if ((e.ctrlKey || e.metaKey) && e.key === 's' && consoleOpen) {
      e.preventDefault();
      saveCurrentScript();
    }
    // Escape to close console when open
    if (e.key === 'Escape' && consoleOpen) {
      consoleOpen = false;
    }
  }

  // Simple syntax highlighting for JavaScript using tokenization
  function highlightCode(code: string): string {
    // Tokenize to avoid regex interference between different token types
    const tokens: { type: string; value: string; start: number; end: number }[] = [];

    // Find all comments first (highest priority)
    const commentRegex = /(\/\/.*$|\/\*[\s\S]*?\*\/)/gm;
    let match;
    while ((match = commentRegex.exec(code)) !== null) {
      tokens.push({ type: 'comment', value: match[0], start: match.index, end: match.index + match[0].length });
    }

    // Find all strings (but not if inside a comment)
    const stringRegex = /(["'`])(?:(?!\1)[^\\]|\\.)*?\1/g;
    while ((match = stringRegex.exec(code)) !== null) {
      const inComment = tokens.some(t => t.type === 'comment' && match!.index >= t.start && match!.index < t.end);
      if (!inComment) {
        tokens.push({ type: 'string', value: match[0], start: match.index, end: match.index + match[0].length });
      }
    }

    // Sort tokens by position
    tokens.sort((a, b) => a.start - b.start);

    // Build result by processing gaps between tokens
    let result = '';
    let pos = 0;

    for (const token of tokens) {
      // Process text before this token (apply keyword/number/function highlighting)
      if (token.start > pos) {
        result += highlightPlainCode(code.slice(pos, token.start));
      }

      // Add the token with its highlighting
      const escaped = token.value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      result += `<span class="hl-${token.type}">${escaped}</span>`;
      pos = token.end;
    }

    // Process remaining text after last token
    if (pos < code.length) {
      result += highlightPlainCode(code.slice(pos));
    }

    return result;
  }

  function highlightPlainCode(code: string): string {
    const keywords = new Set(['const', 'let', 'var', 'function', 'return', 'if', 'else', 'for', 'while', 'async', 'await', 'try', 'catch', 'throw', 'new', 'class', 'extends', 'import', 'export', 'from', 'true', 'false', 'null', 'undefined']);

    // Tokenize by word boundaries and other characters
    const tokenRegex = /([a-zA-Z_]\w*)|(\d+\.?\d*)|([^\w\s])|(\s+)/g;
    let result = '';
    let match;
    let lastIndex = 0;

    while ((match = tokenRegex.exec(code)) !== null) {
      const [full, word, number, punct, space] = match;

      if (word) {
        // Check if it's a function call (followed by parenthesis)
        const rest = code.slice(match.index + word.length);
        const isFunction = /^\s*\(/.test(rest);

        if (keywords.has(word)) {
          result += `<span class="hl-keyword">${word}</span>`;
        } else if (isFunction) {
          result += `<span class="hl-function">${word}</span>`;
        } else {
          result += word;
        }
      } else if (number) {
        result += `<span class="hl-number">${number}</span>`;
      } else if (punct) {
        // Escape HTML special chars
        const escaped = punct === '<' ? '&lt;' : punct === '>' ? '&gt;' : punct === '&' ? '&amp;' : punct;
        result += escaped;
      } else if (space) {
        result += space;
      }

      lastIndex = match.index + full.length;
    }

    return result;
  }

  // Auto-scroll output to bottom
  $effect(() => {
    if (consoleOutputEl && scriptOutput.length > 0) {
      consoleOutputEl.scrollTop = consoleOutputEl.scrollHeight;
    }
  });

  // onMount removed - using $effect instead like original
</script>

<svelte:window onkeydown={handleKeydown} />

<div class="app-container">
  <!-- Top Menu Bar -->
  <div class="top-menu-bar">
    <div class="menu-bar-left">
      <h1 class="app-title">Messpit</h1>
      <div class="menu-bar-divider"></div>
      <div class="project-name-container">
        {#if editingProjectName}
          <input
            type="text"
            class="project-name-input-inline"
            bind:value={projectNameInput}
            onkeydown={(e) => e.key === 'Enter' && saveProjectName()}
            onblur={saveProjectName}
          />
        {:else}
          <button class="project-name-btn" onclick={startEditingProjectName} title="Click to rename">
            {projectInfo.name}
          </button>
        {/if}
        {#if projectInfo.path}
          <span class="saved-dot" title={projectInfo.path}></span>
        {:else}
          <span class="unsaved-dot" title="Unsaved"></span>
        {/if}
      </div>
    </div>
    <div class="menu-bar-actions">
      <button class="menu-bar-btn" onclick={newProject} title="New Project">
        <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z" clip-rule="evenodd" /></svg>
        New
      </button>
      <button class="menu-bar-btn" onclick={openProject} title="Open Project">
        <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" clip-rule="evenodd" /></svg>
        Open
      </button>
      <div class="menu-bar-divider"></div>
      <button class="menu-bar-btn" onclick={saveProject} title="Save Project">
        <svg viewBox="0 0 20 20" fill="currentColor"><path d="M7.707 10.293a1 1 0 10-1.414 1.414l3 3a1 1 0 001.414 0l3-3a1 1 0 00-1.414-1.414L11 11.586V6h5a2 2 0 012 2v7a2 2 0 01-2 2H4a2 2 0 01-2-2V8a2 2 0 012-2h5v5.586l-1.293-1.293zM9 4a1 1 0 012 0v2H9V4z" /></svg>
        Save
      </button>
      <button class="menu-bar-btn" onclick={saveProjectAs} title="Save As...">
        Save As
      </button>
      <div class="menu-bar-divider"></div>
      <button class="menu-bar-btn" onclick={exportProject} title="Export as JSON">
        <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm3.293-7.707a1 1 0 011.414 0L9 10.586V3a1 1 0 112 0v7.586l1.293-1.293a1 1 0 111.414 1.414l-3 3a1 1 0 01-1.414 0l-3-3a1 1 0 010-1.414z" clip-rule="evenodd" /></svg>
        Export
      </button>
      <button class="menu-bar-btn" onclick={importProject} title="Import from JSON">
        <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zM6.293 6.707a1 1 0 010-1.414l3-3a1 1 0 011.414 0l3 3a1 1 0 01-1.414 1.414L11 5.414V13a1 1 0 11-2 0V5.414L7.707 6.707a1 1 0 01-1.414 0z" clip-rule="evenodd" /></svg>
        Import
      </button>
    </div>
  </div>

  <!-- Main Content Area -->
  <div class="app-content">
    <!-- Sidebar -->
    <aside class="sidebar">
      <div class="search-container">
      <svg class="search-icon" viewBox="0 0 20 20" fill="currentColor">
        <path fill-rule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clip-rule="evenodd" />
      </svg>
      <input
        type="text"
        placeholder="Search processes..."
        bind:value={filter}
        class="search-input"
      />
    </div>

    <div class="process-list-header">
      <span class="section-label">Processes</span>
      <button class="icon-button" onclick={loadProcesses} disabled={loading} title="Refresh">
        <svg class="refresh-icon" class:spinning={loading} viewBox="0 0 20 20" fill="currentColor">
          <path fill-rule="evenodd" d="M4 2a1 1 0 011 1v2.101a7.002 7.002 0 0111.601 2.566 1 1 0 11-1.885.666A5.002 5.002 0 005.999 7H9a1 1 0 010 2H4a1 1 0 01-1-1V3a1 1 0 011-1zm.008 9.057a1 1 0 011.276.61A5.002 5.002 0 0014.001 13H11a1 1 0 110-2h5a1 1 0 011 1v5a1 1 0 11-2 0v-2.101a7.002 7.002 0 01-11.601-2.566 1 1 0 01.61-1.276z" clip-rule="evenodd" />
        </svg>
      </button>
    </div>

    <label class="filter-checkbox" title="Show only processes that can be attached to (not hardened)">
      <input type="checkbox" bind:checked={showOnlyAttachable} />
      <span>Attachable only</span>
    </label>

    <div class="process-list">
      {#each filteredProcesses as proc (proc.pid)}
        <div class="process-item-wrapper" class:pinned={pinnedPids.has(proc.pid)}>
          <button
            class="process-item"
            class:selected={selectedPid === proc.pid}
            onclick={() => attachToProcess(proc.pid)}
            type="button"
          >
            <div class="process-icon" class:attachable-icon={proc.attachable}>
              <svg viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M2 5a2 2 0 012-2h12a2 2 0 012 2v10a2 2 0 01-2 2H4a2 2 0 01-2-2V5zm3.293 1.293a1 1 0 011.414 0l3 3a1 1 0 010 1.414l-3 3a1 1 0 01-1.414-1.414L7.586 10 5.293 7.707a1 1 0 010-1.414z" clip-rule="evenodd" />
              </svg>
            </div>
            <div class="process-info">
              <span class="process-name">{proc.name}</span>
              <span class="process-details">
                <span class="process-pid">PID {proc.pid}</span>
                {#if proc.path}
                  <span class="process-path" title={proc.path}>{formatProcessPath(proc.path)}</span>
                {/if}
              </span>
            </div>
          </button>
          <button
            class="pin-btn"
            class:pinned={pinnedPids.has(proc.pid)}
            onclick={(e) => { e.stopPropagation(); togglePinProcess(proc.pid); }}
            title={pinnedPids.has(proc.pid) ? "Unpin process" : "Pin process"}
            type="button"
          >
            <svg viewBox="0 0 20 20" fill="currentColor">
              <path d="M9.828 3.172a4 4 0 015.657 5.657L10 14.314l-5.485-5.485a4 4 0 115.657-5.657l.354.353.353-.353z" />
            </svg>
          </button>
        </div>
      {:else}
        <div class="empty-state">
          {#if loading}
            <div class="loading-spinner"></div>
            <span>Loading processes...</span>
          {:else}
            <span>No processes found</span>
          {/if}
        </div>
      {/each}
    </div>

    <div class="sidebar-footer">
      <span class="process-count">
        {filteredProcesses.length} of {processes.length} processes
      </span>
    </div>
  </aside>

  <!-- Main Content -->
  <main class="main-content">
    {#if error}
      <div class="error-banner">
        <svg viewBox="0 0 20 20" fill="currentColor">
          <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
        </svg>
        <span>{error}</span>
        <button class="dismiss-btn" onclick={dismissError} title="Dismiss error">
          <svg viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd" />
          </svg>
        </button>
      </div>
    {/if}

    {#if attachedProcess}
      <!-- Connected state -->
      <div class="connected-header">
        <div class="connection-badge">
          <div class="pulse-dot"></div>
          <span>Connected</span>
        </div>
        <div class="connected-info">
          <h2>{attachedProcess.name}</h2>
          <p>PID {attachedProcess.pid} · {attachedProcess.arch}</p>
        </div>
        <button class="btn btn-secondary" onclick={detach} title="Detach from process">
          Disconnect
        </button>
      </div>
    {:else}
      <!-- Disconnected state -->
      <div class="disconnected-header">
        <span class="disconnected-badge">No Process</span>
        <span class="disconnected-hint">Select a process from the sidebar, or use Watch tab to manage addresses</span>
      </div>
    {/if}

      <!-- Tab Navigation (always visible) -->
      <div class="tab-bar">
        <button
          class="tab-item"
          class:active={activeTab === "scan"}
          onclick={() => activeTab = "scan"}
          type="button"
          title="Search for values in memory"
        >
          <svg viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clip-rule="evenodd" />
          </svg>
          Scanner
          {#if totalScanResults > 0}
            <span class="badge">{totalScanResults > 1000 ? "1000+" : totalScanResults}</span>
          {/if}
        </button>
        <button
          class="tab-item"
          class:active={activeTab === "watch"}
          onclick={() => { activeTab = "watch"; loadWatches(); }}
          type="button"
          title="Monitor and edit memory addresses"
        >
          <svg viewBox="0 0 20 20" fill="currentColor">
            <path d="M10 12a2 2 0 100-4 2 2 0 000 4z" />
            <path fill-rule="evenodd" d="M.458 10C1.732 5.943 5.522 3 10 3s8.268 2.943 9.542 7c-1.274 4.057-5.064 7-9.542 7S1.732 14.057.458 10zM14 10a4 4 0 11-8 0 4 4 0 018 0z" clip-rule="evenodd" />
          </svg>
          Watch
          {#if watches.length > 0}
            <span class="badge">{watches.length}</span>
          {/if}
        </button>
        <button
          class="tab-item"
          class:active={activeTab === "regions"}
          onclick={() => { activeTab = "regions"; loadRegions(); }}
          type="button"
          title="View process memory regions"
        >
          <svg viewBox="0 0 20 20" fill="currentColor">
            <path d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H4a1 1 0 01-1-1v-6zM14 9a1 1 0 00-1 1v6a1 1 0 001 1h2a1 1 0 001-1v-6a1 1 0 00-1-1h-2z" />
          </svg>
          Memory
        </button>
        <button
          class="tab-item"
          class:active={activeTab === "patterns"}
          onclick={() => { activeTab = "patterns"; loadSignatures(); }}
          type="button"
          title="Scan for byte patterns and manage signatures"
        >
          <svg viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M3 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1z" clip-rule="evenodd" />
          </svg>
          Patterns
          {#if signatures.length > 0}
            <span class="badge">{signatures.length}</span>
          {/if}
        </button>
        <!-- Console toggle on the right side of tab bar -->
        <div class="tab-spacer"></div>
        <button
          class="tab-item console-toggle"
          class:active={consoleOpen}
          onclick={() => { consoleOpen = !consoleOpen; if (consoleOpen) { loadScriptApiTypes(); loadSavedScripts(); } }}
          type="button"
          title="Toggle script console"
        >
          <svg viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M2 5a2 2 0 012-2h12a2 2 0 012 2v10a2 2 0 01-2 2H4a2 2 0 01-2-2V5zm3.293 1.293a1 1 0 011.414 0l3 3a1 1 0 010 1.414l-3 3a1 1 0 01-1.414-1.414L7.586 10 5.293 7.707a1 1 0 010-1.414zM11 12a1 1 0 100 2h3a1 1 0 100-2h-3z" clip-rule="evenodd" />
          </svg>
          Console
          {#if scriptRunning}
            <div class="btn-spinner-small"></div>
          {/if}
        </button>
      </div>

      <!-- Tab Content -->
      <div class="tab-content">
        {#if activeTab === "scan"}
          <div class="scan-panel">
            {#if !attachedProcess}
              <div class="requires-process">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M8.25 3v1.5M4.5 8.25H3m18 0h-1.5M4.5 12H3m18 0h-1.5m-15 3.75H3m18 0h-1.5M8.25 19.5V21M12 3v1.5m0 15V21m3.75-18v1.5m0 15V21m-9-1.5h10.5a2.25 2.25 0 002.25-2.25V6.75a2.25 2.25 0 00-2.25-2.25H6.75A2.25 2.25 0 004.5 6.75v10.5a2.25 2.25 0 002.25 2.25z" />
                </svg>
                <h3>Process Required</h3>
                <p>Select a process from the sidebar to scan its memory</p>
              </div>
            {:else if wizardMode}
              <!-- Guided Scan Wizard -->
              <div class="wizard-container">
                <div class="wizard-header">
                  <div class="wizard-title">
                    <h3>Guided Scan Wizard</h3>
                    <span class="wizard-step-indicator">Step {wizardStep} of 4</span>
                  </div>
                  <button class="btn btn-sm btn-secondary" onclick={exitWizard}>
                    Exit Wizard
                  </button>
                </div>

                <div class="wizard-progress">
                  <div class="wizard-progress-bar" style="width: {wizardStep * 25}%"></div>
                </div>

                <div class="wizard-content">
                  {#if wizardStep === 1}
                    <!-- Step 1: Initial Setup -->
                    <div class="wizard-step">
                      <div class="wizard-step-header">
                        <span class="wizard-step-number">1</span>
                        <div>
                          <h4>What are you looking for?</h4>
                          <p>Enter the current value you see in the game</p>
                        </div>
                      </div>

                      <div class="wizard-form">
                        <div class="form-group">
                          <label class="form-label" for="wizard-name">Name (optional)</label>
                          <input
                            id="wizard-name"
                            type="text"
                            class="form-input"
                            placeholder="e.g., Health, Ammo, Money..."
                            bind:value={wizardValueName}
                          />
                        </div>

                        <div class="form-row">
                          <div class="form-group">
                            <label class="form-label" for="wizard-type">Value Type</label>
                            <select id="wizard-type" class="form-select" bind:value={scanValueType}>
                              <option value="i32">Integer (most common)</option>
                              <option value="f32">Decimal (Float)</option>
                              <option value="f64">Decimal (Double)</option>
                              <option value="i64">Large Integer</option>
                              <option value="string">Text/String</option>
                            </select>
                          </div>
                          {#if scanValueType === "string"}
                            <div class="form-group" style="width: 80px;">
                              <label class="form-label" for="wizard-strlen">Max Len</label>
                              <input
                                id="wizard-strlen"
                                type="number"
                                class="form-input"
                                min="1"
                                max="4096"
                                bind:value={stringMaxLen}
                              />
                            </div>
                          {/if}
                          <div class="form-group flex-1">
                            <label class="form-label" for="wizard-value">Current Value</label>
                            <input
                              id="wizard-value"
                              type="text"
                              class="form-input"
                              placeholder={scanValueType === "string" ? "e.g., PlayerName" : "e.g., 100"}
                              bind:value={scanValue}
                              onkeydown={(e) => e.key === 'Enter' && wizardFirstScan()}
                            />
                          </div>
                        </div>

                        <div class="wizard-tip">
                          <strong>Tip:</strong> Look at the game and note the exact value (e.g., if health shows "100", enter 100)
                        </div>

                        <button class="btn btn-primary btn-lg" onclick={wizardFirstScan} disabled={scanning}>
                          {#if scanning}
                            <div class="btn-spinner"></div>
                            Scanning...
                          {:else}
                            Start Scanning
                          {/if}
                        </button>
                      </div>
                    </div>
                  {:else if wizardStep === 2}
                    <!-- Step 2: Refine -->
                    <div class="wizard-step">
                      <div class="wizard-step-header">
                        <span class="wizard-step-number">2</span>
                        <div>
                          <h4>Narrow down the results</h4>
                          <p>Found {totalScanResults.toLocaleString()} possible addresses</p>
                        </div>
                      </div>

                      <div class="wizard-form">
                        <div class="wizard-instruction">
                          <strong>Now change the value in the game</strong> (e.g., take damage, spend money, use ammo)
                        </div>

                        <div class="wizard-refine-options">
                          <button type="button" class="refine-option" onclick={() => wizardRefine("changed")}>
                            <div class="refine-option-icon">↕</div>
                            <div class="refine-option-text">
                              <strong>Value Changed</strong>
                              <span>I changed the value but don't know the new amount</span>
                            </div>
                          </button>

                          <button type="button" class="refine-option" onclick={() => wizardRefine("decreased")}>
                            <div class="refine-option-icon">↓</div>
                            <div class="refine-option-text">
                              <strong>Value Decreased</strong>
                              <span>The value went down (took damage, spent money)</span>
                            </div>
                          </button>

                          <button type="button" class="refine-option" onclick={() => wizardRefine("increased")}>
                            <div class="refine-option-icon">↑</div>
                            <div class="refine-option-text">
                              <strong>Value Increased</strong>
                              <span>The value went up (healed, earned money)</span>
                            </div>
                          </button>

                          <div class="refine-option exact-option">
                            <div class="refine-option-icon">=</div>
                            <div class="refine-option-text flex-1">
                              <strong>I know the exact new value</strong>
                              <input
                                type="text"
                                class="form-input mt-8"
                                placeholder="Enter new value..."
                                bind:value={scanValue}
                                onkeydown={(e) => e.key === 'Enter' && wizardRefine("exact")}
                              />
                            </div>
                            <button class="btn btn-primary" onclick={() => wizardRefine("exact")} disabled={scanning}>
                              {scanning ? "..." : "Scan"}
                            </button>
                          </div>
                        </div>

                        <div class="wizard-tip">
                          <strong>Tip:</strong> Keep refining until you have fewer than 10 results
                        </div>

                        <button class="btn btn-secondary" onclick={wizardReset}>
                          Start Over
                        </button>
                      </div>
                    </div>
                  {:else if wizardStep === 3}
                    <!-- Step 3: Select Result -->
                    <div class="wizard-step">
                      <div class="wizard-step-header">
                        <span class="wizard-step-number">3</span>
                        <div>
                          <h4>Select the correct address</h4>
                          <p>Found {totalScanResults} potential matches</p>
                        </div>
                      </div>

                      <div class="wizard-results">
                        {#each scanResults as result (result.address)}
                          <button type="button" class="wizard-result-item" onclick={() => wizardAddToWatch(result.address, result.value)}>
                            <div class="wizard-result-info">
                              <span class="mono">{result.address}</span>
                              <span class="wizard-result-value">{result.value}</span>
                            </div>
                            <span class="btn btn-primary btn-sm">
                              Select This
                            </span>
                          </button>
                        {/each}
                      </div>

                      <div class="wizard-tip">
                        <strong>Tip:</strong> If unsure, try changing the value in-game and watch which address updates
                      </div>

                      <div class="wizard-actions">
                        <button class="btn btn-secondary" onclick={() => wizardStep = 2}>
                          Continue Refining
                        </button>
                      </div>
                    </div>
                  {:else if wizardStep === 4}
                    <!-- Step 4: Success -->
                    <div class="wizard-step wizard-success">
                      <div class="wizard-success-icon">✓</div>
                      <h4>Success!</h4>
                      <p>The address has been added to your Watch List</p>

                      <div class="wizard-next-steps">
                        <p><strong>What's next?</strong></p>
                        <ul>
                          <li>Go to the <strong>Watch</strong> tab to see your value</li>
                          <li>Click the <strong>freeze</strong> button to lock the value</li>
                          <li>Double-click to edit the value directly</li>
                        </ul>
                      </div>

                      <div class="wizard-actions">
                        <button class="btn btn-primary" onclick={() => { activeTab = "watch"; exitWizard(); }}>
                          Go to Watch List
                        </button>
                        <button class="btn btn-secondary" onclick={wizardReset}>
                          Find Another Value
                        </button>
                      </div>
                    </div>
                  {/if}
                </div>

                <!-- History sidebar -->
                {#if wizardHistory.length > 0}
                  <div class="wizard-history">
                    <h5>History</h5>
                    {#each wizardHistory as item, i}
                      <div class="wizard-history-item">{i + 1}. {item}</div>
                    {/each}
                  </div>
                {/if}
              </div>
            {:else}
              <!-- Regular Scan Mode -->
              <div class="card">
                <div class="card-header">
                  <h3>{hasPreviousScan ? "Refine Scan" : "New Scan"}</h3>
                  <div class="header-actions">
                    {#if !hasPreviousScan}
                      <button class="btn btn-sm btn-accent" onclick={startWizard} title="Step-by-step wizard for beginners">
                        <svg viewBox="0 0 20 20" fill="currentColor" style="width:14px;height:14px;margin-right:4px">
                          <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-8-3a1 1 0 00-.867.5 1 1 0 11-1.731-1A3 3 0 0113 8a3.001 3.001 0 01-2 2.83V11a1 1 0 11-2 0v-1a1 1 0 011-1 1 1 0 100-2zm0 8a1 1 0 100-2 1 1 0 000 2z" clip-rule="evenodd" />
                        </svg>
                        Guided Mode
                      </button>
                    {/if}
                    {#if hasPreviousScan}
                      <button class="btn btn-sm btn-secondary" onclick={clearScan} title="Clear results and start fresh">
                        New Scan
                      </button>
                    {/if}
                  </div>
                </div>
                <div class="card-body">
                  {#if !hasPreviousScan}
                    <div class="form-row">
                      <div class="form-group">
                        <label class="form-label" for="scan-type">Type</label>
                        <select id="scan-type" class="form-select" bind:value={scanValueType}>
                          <option value="i32">Int32</option>
                          <option value="i64">Int64</option>
                          <option value="u32">UInt32</option>
                          <option value="u64">UInt64</option>
                          <option value="f32">Float</option>
                          <option value="f64">Double</option>
                          <option value="string">String</option>
                        </select>
                      </div>
                      {#if scanValueType === "string"}
                        <div class="form-group" style="width: 80px;">
                          <label class="form-label" for="scan-strlen">Max Len</label>
                          <input
                            id="scan-strlen"
                            type="number"
                            class="form-input"
                            min="1"
                            max="4096"
                            bind:value={stringMaxLen}
                          />
                        </div>
                      {/if}
                      <div class="form-group flex-1">
                        <label class="form-label" for="scan-value">Value</label>
                        <input
                          id="scan-value"
                          type="text"
                          class="form-input"
                          placeholder={scanValueType === "string" ? "Enter text to find..." : "Enter value to find..."}
                          bind:value={scanValue}
                          onkeydown={(e) => e.key === 'Enter' && startScan()}
                        />
                      </div>
                      <div class="form-group">
                        <span class="form-label" aria-hidden="true">&nbsp;</span>
                        <button class="btn btn-primary" onclick={startScan} disabled={scanning}>
                          {#if scanning}
                            <div class="btn-spinner"></div>
                            Scanning...
                          {:else}
                            First Scan
                          {/if}
                        </button>
                      </div>
                    </div>
                  {:else}
                  <div class="refine-section">
                    <div class="refine-modes">
                      <button
                        class="refine-btn"
                        class:active={refineMode === "changed"}
                        onclick={() => refineMode = "changed"}
                        title="Keep addresses where value changed"
                      >
                        Changed
                      </button>
                      <button
                        class="refine-btn"
                        class:active={refineMode === "unchanged"}
                        onclick={() => refineMode = "unchanged"}
                        title="Keep addresses where value stayed the same"
                      >
                        Unchanged
                      </button>
                      <button
                        class="refine-btn"
                        class:active={refineMode === "increased"}
                        onclick={() => refineMode = "increased"}
                        title="Keep addresses where value went up"
                      >
                        Increased
                      </button>
                      <button
                        class="refine-btn"
                        class:active={refineMode === "decreased"}
                        onclick={() => refineMode = "decreased"}
                        title="Keep addresses where value went down"
                      >
                        Decreased
                      </button>
                      <button
                        class="refine-btn"
                        class:active={refineMode === "exact"}
                        onclick={() => refineMode = "exact"}
                        title="Keep addresses matching a specific value"
                      >
                        Exact Value
                      </button>
                    </div>
                    {#if refineMode === "exact"}
                      <div class="form-row mt-12">
                        <div class="form-group flex-1">
                          <input
                            type="text"
                            class="form-input"
                            placeholder="Enter new value..."
                            bind:value={scanValue}
                            onkeydown={(e) => e.key === 'Enter' && refineScan()}
                          />
                        </div>
                        <button class="btn btn-primary" onclick={refineScan} disabled={scanning}>
                          {#if scanning}
                            <div class="btn-spinner"></div>
                            Refining...
                          {:else}
                            Next Scan
                          {/if}
                        </button>
                      </div>
                    {:else}
                      <div class="form-row mt-12">
                        <button class="btn btn-primary flex-1" onclick={refineScan} disabled={scanning}>
                          {#if scanning}
                            <div class="btn-spinner"></div>
                            Refining...
                          {:else}
                            Next Scan
                          {/if}
                        </button>
                      </div>
                    {/if}
                  </div>
                {/if}
              </div>
            </div>

            <div class="card flex-1">
              <div class="card-header">
                <h3>Results</h3>
                <span class="results-count">
                  {totalScanResults}{totalScanResults >= 1000 ? "+" : ""} found
                  {#if scanResults.length < totalScanResults}
                    (showing {scanResults.length})
                  {/if}
                </span>
              </div>
              <div class="results-table-container">
                {#if scanResults.length > 0}
                  <table class="results-table">
                    <thead>
                      <tr>
                        <th>Address</th>
                        <th>Value</th>
                        <th></th>
                      </tr>
                    </thead>
                    <tbody>
                      {#each scanResults as result (result.address)}
                        <tr>
                          <td class="mono">{result.address}</td>
                          <td class="value-cell">{result.value}</td>
                          <td class="actions-cell">
                            <button
                              class="action-btn"
                              title="Add to watch list"
                              onclick={() => addToWatch(result.address, result.value)}
                            >
                              <svg viewBox="0 0 20 20" fill="currentColor">
                                <path d="M10 12a2 2 0 100-4 2 2 0 000 4z" />
                                <path fill-rule="evenodd" d="M.458 10C1.732 5.943 5.522 3 10 3s8.268 2.943 9.542 7c-1.274 4.057-5.064 7-9.542 7S1.732 14.057.458 10zM14 10a4 4 0 11-8 0 4 4 0 018 0z" clip-rule="evenodd" />
                              </svg>
                            </button>
                          </td>
                        </tr>
                      {/each}
                    </tbody>
                  </table>
                {:else}
                  <div class="empty-results">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                      <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
                    </svg>
                    <p>No results yet</p>
                    <span>Enter a value and click First Scan to find memory addresses</span>
                  </div>
                {/if}
              </div>
            </div>
          {/if}
          </div>
        {:else if activeTab === "watch"}
          <div class="watch-panel">
            <!-- Manual Entry Card -->
            <div class="card">
              <div class="card-header">
                <h3>Add Watch Entry</h3>
                <button class="btn btn-sm btn-secondary" onclick={() => showManualEntry = !showManualEntry} title={showManualEntry ? "Cancel manual entry" : "Manually add an address to watch"}>
                  {showManualEntry ? "Cancel" : "+ Add Manual"}
                </button>
              </div>
              {#if showManualEntry}
                <div class="card-body manual-entry-form">
                  <div class="form-row">
                    <div class="form-group flex-1">
                      <label class="form-label" for="manual-address">Address</label>
                      <input
                        id="manual-address"
                        type="text"
                        class="form-input mono"
                        bind:value={manualAddress}
                        placeholder="0x12345678"
                      />
                    </div>
                    <div class="form-group">
                      <label class="form-label" for="manual-type">Type</label>
                      <select id="manual-type" class="form-select" bind:value={manualValueType}>
                        <option value="i32">Int32</option>
                        <option value="i64">Int64</option>
                        <option value="f32">Float</option>
                        <option value="f64">Double</option>
                        <option value="u32">UInt32</option>
                        <option value="u64">UInt64</option>
                        <option value="i8">Int8</option>
                        <option value="i16">Int16</option>
                        <option value="u8">UInt8</option>
                        <option value="u16">UInt16</option>
                        <option value="string">String</option>
                      </select>
                    </div>
                    {#if manualValueType === "string"}
                      <div class="form-group" style="width: 80px;">
                        <label class="form-label" for="manual-strlen">Max Len</label>
                        <input
                          id="manual-strlen"
                          type="number"
                          class="form-input"
                          min="1"
                          max="4096"
                          bind:value={manualStringMaxLen}
                        />
                      </div>
                    {/if}
                    <div class="form-group flex-1">
                      <label class="form-label" for="manual-label">Label (optional)</label>
                      <input
                        id="manual-label"
                        type="text"
                        class="form-input"
                        bind:value={manualLabel}
                        placeholder="Health, Ammo, etc."
                      />
                    </div>
                    <div class="form-group">
                      <span class="form-label" aria-hidden="true">&nbsp;</span>
                      <button class="btn btn-primary" onclick={addManualWatch} title="Add address to watch list">
                        Add
                      </button>
                    </div>
                  </div>
                </div>
              {/if}
            </div>

            <!-- Watch List -->
            <div class="card flex-1">
              <div class="card-header">
                <h3>Watch List</h3>
                <div class="header-right">
                  {#if !attachedProcess}
                    <span class="offline-badge">Offline</span>
                  {/if}
                  <span class="results-count">{watches.length} entries</span>
                </div>
              </div>
              <div class="results-table-container">
                {#if watches.length > 0}
                  <table class="results-table">
                    <thead>
                      <tr>
                        <th>Label</th>
                        <th>Address</th>
                        <th>Type</th>
                        <th>Value</th>
                        <th></th>
                      </tr>
                    </thead>
                    <tbody>
                      {#each watches as watch (watch.id)}
                        <tr class:frozen={watch.frozen} class:editing={editingWatchId === watch.id} class:value-changed={changedWatchIds.has(watch.id)}>
                          <td class="label-cell">{watch.label}</td>
                          <td class="mono">{watch.address}</td>
                          <td class="type-cell">{watch.value_type}</td>
                          <td class="value-cell">
                            {#if editingWatchId === watch.id}
                              <div class="value-edit-container">
                                <input
                                  type="text"
                                  class="value-edit-input"
                                  bind:value={editingWatchValue}
                                  placeholder="Enter value"
                                  onkeydown={(e) => {
                                    if (e.key === 'Enter') writeWatchValue(watch);
                                    if (e.key === 'Escape') cancelEditingWatch();
                                  }}
                                />
                                <button class="btn btn-sm btn-primary" onclick={() => writeWatchValue(watch)} disabled={!attachedProcess} title={attachedProcess ? "Write to memory" : "Attach to process first"}>
                                  Write
                                </button>
                                <button class="btn btn-sm btn-secondary" onclick={cancelEditingWatch}>
                                  Cancel
                                </button>
                              </div>
                            {:else}
                              <span class="value-display" class:no-value={!watch.value} class:changed={changedWatchIds.has(watch.id)}>
                                {watch.value ?? (attachedProcess ? "—" : "N/A")}
                              </span>
                            {/if}
                          </td>
                          <td class="actions-cell">
                            {#if editingWatchId !== watch.id}
                              <button
                                class="action-btn"
                                title="Edit value"
                                onclick={() => startEditingWatch(watch)}
                              >
                                <svg viewBox="0 0 20 20" fill="currentColor">
                                  <path d="M13.586 3.586a2 2 0 112.828 2.828l-.793.793-2.828-2.828.793-.793zM11.379 5.793L3 14.172V17h2.828l8.38-8.379-2.83-2.828z" />
                                </svg>
                              </button>
                              <button
                                class="action-btn"
                                class:active={watch.frozen}
                                title={watch.frozen ? "Unfreeze" : "Freeze value"}
                                onclick={() => toggleFreeze(watch)}
                                disabled={!attachedProcess}
                              >
                                <svg viewBox="0 0 20 20" fill="currentColor">
                                  {#if watch.frozen}
                                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8 7a1 1 0 00-1 1v4a1 1 0 001 1h4a1 1 0 001-1V8a1 1 0 00-1-1H8z" clip-rule="evenodd" />
                                  {:else}
                                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM9.555 7.168A1 1 0 008 8v4a1 1 0 001.555.832l3-2a1 1 0 000-1.664l-3-2z" clip-rule="evenodd" />
                                  {/if}
                                </svg>
                              </button>
                              <button
                                class="action-btn delete"
                                title="Remove from watch"
                                onclick={() => removeWatch(watch.id)}
                              >
                                <svg viewBox="0 0 20 20" fill="currentColor">
                                  <path fill-rule="evenodd" d="M9 2a1 1 0 00-.894.553L7.382 4H4a1 1 0 000 2v10a2 2 0 002 2h8a2 2 0 002-2V6a1 1 0 100-2h-3.382l-.724-1.447A1 1 0 0011 2H9zM7 8a1 1 0 012 0v6a1 1 0 11-2 0V8zm5-1a1 1 0 00-1 1v6a1 1 0 102 0V8a1 1 0 00-1-1z" clip-rule="evenodd" />
                                </svg>
                              </button>
                            {/if}
                          </td>
                        </tr>
                      {/each}
                    </tbody>
                  </table>
                {:else}
                  <div class="empty-results">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                      <path stroke-linecap="round" stroke-linejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 6.918 4.5 12 4.5c5.082 0 8.577 3.01 9.964 7.183.07.207.07.431 0 .639C20.577 16.49 17.082 19.5 12 19.5c-5.082 0-8.577-3.01-9.964-7.178z" />
                      <path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                    </svg>
                    <p>No watch entries</p>
                    <span>Click "+ Add Manual" above or add addresses from the Scanner tab</span>
                  </div>
                {/if}
              </div>
            </div>
          </div>
        {:else if activeTab === "regions"}
          <div class="regions-panel">
            {#if !attachedProcess}
              <div class="requires-process">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H4a1 1 0 01-1-1v-6zM14 9a1 1 0 00-1 1v6a1 1 0 001 1h2a1 1 0 001-1v-6a1 1 0 00-1-1h-2z" />
                </svg>
                <h3>Process Required</h3>
                <p>Select a process from the sidebar to view its memory regions</p>
              </div>
            {:else}
              <div class="card flex-1">
                <div class="card-header">
                  <h3>Memory Regions</h3>
                  <span class="results-count">{filteredRegions.length} shown / {regions.length} total</span>
                </div>

                <!-- Regions Toolbar -->
                <div class="regions-toolbar">
                  <div class="regions-filters">
                    <label class="toggle-label">
                      <input type="checkbox" bind:checked={regionShowAll} />
                      <span>Show all regions</span>
                    </label>
                    <input
                      type="text"
                      class="form-input form-input-sm"
                      placeholder="Filter by module..."
                      bind:value={regionModuleFilter}
                    />
                    {#if regionModuleFilter}
                      <button class="btn-clear" onclick={() => regionModuleFilter = ""} title="Clear filter">×</button>
                    {/if}
                  </div>
                  <span class="regions-hint">Click column headers to sort</span>
                </div>

                <div class="regions-table-container">
                  {#if loadingRegions}
                    <div class="loading-state">
                      <div class="loading-spinner"></div>
                      <span>Loading regions...</span>
                    </div>
                  {:else if filteredRegions.length > 0}
                    <table class="regions-table">
                      <thead>
                        <tr>
                          <th class="col-addr sortable" class:sorted={regionSortBy === "address"} onclick={() => toggleRegionSort("address")}>
                            Start {regionSortBy === "address" ? (regionSortAsc ? "↑" : "↓") : ""}
                          </th>
                          <th class="col-addr">End</th>
                          <th class="col-size sortable" class:sorted={regionSortBy === "size"} onclick={() => toggleRegionSort("size")}>
                            Size {regionSortBy === "size" ? (regionSortAsc ? "↑" : "↓") : ""}
                          </th>
                          <th class="col-perms sortable" class:sorted={regionSortBy === "perms"} onclick={() => toggleRegionSort("perms")}>
                            Perms {regionSortBy === "perms" ? (regionSortAsc ? "↑" : "↓") : ""}
                          </th>
                          <th class="col-module sortable" class:sorted={regionSortBy === "module"} onclick={() => toggleRegionSort("module")}>
                            Module {regionSortBy === "module" ? (regionSortAsc ? "↑" : "↓") : ""}
                          </th>
                          <th class="col-actions"></th>
                        </tr>
                      </thead>
                      <tbody>
                        {#each filteredRegions as region (region.start)}
                          <tr class:non-writable={!region.writable}>
                            <td class="col-addr">
                              <button
                                class="addr-btn mono"
                                onclick={() => copyToClipboard(region.start)}
                                title="Click to copy"
                              >{region.start}</button>
                            </td>
                            <td class="col-addr">
                              <button
                                class="addr-btn mono"
                                onclick={() => copyToClipboard(region.end)}
                                title="Click to copy"
                              >{region.end}</button>
                            </td>
                            <td class="col-size">{formatSize(region.size)}</td>
                            <td class="col-perms">
                              <span class="region-perms">
                                <span class="perm" class:active={region.readable}>R</span><span class="perm" class:active={region.writable}>W</span><span class="perm" class:active={region.executable}>X</span>
                              </span>
                            </td>
                            <td class="col-module">
                              {#if region.module}
                                <button
                                  class="region-module"
                                  title="Click to filter by this module"
                                  onclick={() => regionModuleFilter = region.module || ""}
                                >{region.module}</button>
                              {:else}
                                <span class="no-module">-</span>
                              {/if}
                            </td>
                            <td class="col-actions">
                              {#if region.readable}
                                <button
                                  class="btn-view"
                                  onclick={() => openMemoryViewer(region)}
                                  title="Open in Memory Viewer"
                                >View</button>
                              {/if}
                            </td>
                          </tr>
                        {/each}
                      </tbody>
                    </table>
                    {#if regionTotalPages > 1}
                      <div class="pagination">
                        <button
                          class="pagination-btn"
                          onclick={() => loadRegions(0, false)}
                          disabled={regionPage === 0 || loadingRegions}
                          title="First page"
                        >««</button>
                        <button
                          class="pagination-btn"
                          onclick={() => loadRegions(Math.max(0, regionPage - 1), false)}
                          disabled={regionPage === 0 || loadingRegions}
                          title="Previous page"
                        >«</button>
                        <span class="pagination-info">
                          Page {regionPage + 1} of {regionTotalPages}
                          <span class="pagination-range">
                            (showing {filteredRegions.length} of {totalRegions} total)
                          </span>
                        </span>
                        <button
                          class="pagination-btn"
                          onclick={() => loadRegions(Math.min(regionTotalPages - 1, regionPage + 1), false)}
                          disabled={regionPage >= regionTotalPages - 1 || loadingRegions}
                          title="Next page"
                        >»</button>
                        <button
                          class="pagination-btn"
                          onclick={() => loadRegions(regionTotalPages - 1, false)}
                          disabled={regionPage >= regionTotalPages - 1 || loadingRegions}
                          title="Last page"
                        >»»</button>
                      </div>
                    {/if}
                  {:else if regions.length > 0}
                    <div class="empty-results">
                      <p>No regions match filters</p>
                      <button class="btn btn-secondary btn-sm" onclick={() => { regionShowAll = true; regionModuleFilter = ""; }}>
                        Clear filters
                      </button>
                    </div>
                  {:else}
                    <div class="empty-results">
                      <p>No memory regions found</p>
                    </div>
                  {/if}
                </div>
              </div>
            {/if}
          </div>
        {:else if activeTab === "patterns"}
          <div class="patterns-panel">
            <!-- Pattern Scan Section -->
            <div class="card">
              <div class="card-header">
                <h3>Pattern Scan</h3>
              </div>
              <div class="card-body">
                <div class="form-row">
                  <div class="form-group flex-1">
                    <label class="form-label" for="pattern-input">Pattern (IDA format)</label>
                    <input
                      id="pattern-input"
                      type="text"
                      class="form-input mono"
                      bind:value={patternInput}
                      placeholder="48 8B ?? ?? 00"
                    />
                  </div>
                  <div class="form-group">
                    <label class="form-label" for="pattern-module">Module (optional)</label>
                    <input
                      id="pattern-module"
                      type="text"
                      class="form-input"
                      bind:value={patternModule}
                      placeholder="game.exe"
                    />
                  </div>
                  <div class="form-group">
                    <span class="form-label" aria-hidden="true">&nbsp;</span>
                    <button class="btn btn-primary" onclick={runPatternScan} disabled={patternScanning || !attachedProcess} title={attachedProcess ? "Search memory for byte pattern" : "Attach to a process first"}>
                      {#if patternScanning}
                        <span class="btn-spinner-small"></span>
                        Scanning...
                      {:else}
                        Scan
                      {/if}
                    </button>
                  </div>
                </div>
                <div class="pattern-tip">
                  Use <code>??</code> or <code>*</code> for wildcard bytes. Example: <code>48 8B ?? 00 ?? ?? 48</code>
                </div>
              </div>
            </div>

            <!-- Pattern Results -->
            {#if patternResults.length > 0}
              <div class="card flex-1">
                <div class="card-header">
                  <h3>Results</h3>
                  <span class="results-count">{patternResults.length} matches</span>
                </div>
                <div class="results-table-container">
                  <table class="results-table">
                    <thead>
                      <tr>
                        <th>Address</th>
                        <th>Module</th>
                        <th>Offset</th>
                        <th></th>
                      </tr>
                    </thead>
                    <tbody>
                      {#each patternResults as result (result.address)}
                        <tr>
                          <td class="mono">{result.address}</td>
                          <td>{result.module || "-"}</td>
                          <td class="mono">{result.module_offset || "-"}</td>
                          <td class="actions-cell">
                            <button
                              class="action-btn"
                              title="Save as signature"
                              onclick={() => promoteToSignature(result)}
                            >
                              <svg viewBox="0 0 20 20" fill="currentColor">
                                <path d="M5 4a2 2 0 012-2h6a2 2 0 012 2v14l-5-2.5L5 18V4z" />
                              </svg>
                            </button>
                          </td>
                        </tr>
                      {/each}
                    </tbody>
                  </table>
                </div>
              </div>
            {/if}

            <!-- Saved Signatures -->
            <div class="card">
              <div class="card-header">
                <h3>Saved Signatures</h3>
                <button class="btn btn-sm btn-secondary" onclick={() => showAddSignature = !showAddSignature} title={showAddSignature ? "Cancel adding signature" : "Manually add a new signature"}>
                  {showAddSignature ? "Cancel" : "+ Add"}
                </button>
              </div>

              {#if showAddSignature}
                <div class="card-body signature-form">
                  <div class="form-row">
                    <div class="form-group flex-1">
                      <label class="form-label" for="sig-label">Label</label>
                      <input id="sig-label" type="text" class="form-input" bind:value={newSigLabel} placeholder="Health Pointer" />
                    </div>
                    <div class="form-group">
                      <label class="form-label" for="sig-type">Type</label>
                      <select id="sig-type" class="form-select" bind:value={newSigValueType}>
                        <option value="i32">Int32</option>
                        <option value="i64">Int64</option>
                        <option value="f32">Float</option>
                        <option value="f64">Double</option>
                      </select>
                    </div>
                  </div>
                  <div class="form-row">
                    <div class="form-group flex-1">
                      <label class="form-label" for="sig-pattern">Pattern</label>
                      <input id="sig-pattern" type="text" class="form-input mono" bind:value={newSigPattern} placeholder="48 8B ?? 00" />
                    </div>
                    <div class="form-group">
                      <label class="form-label" for="sig-module">Module</label>
                      <input id="sig-module" type="text" class="form-input" bind:value={newSigModule} placeholder="game.exe" />
                    </div>
                    <div class="form-group">
                      <label class="form-label" for="sig-offset">Offset</label>
                      <input id="sig-offset" type="number" class="form-input" bind:value={newSigOffset} placeholder="0" />
                    </div>
                  </div>
                  <div class="form-actions">
                    <button class="btn btn-primary" onclick={addSignature} title="Save this pattern as a reusable signature">Save Signature</button>
                  </div>
                </div>
              {/if}

              <div class="results-table-container">
                {#if signatures.length > 0}
                  <table class="results-table">
                    <thead>
                      <tr>
                        <th>Label</th>
                        <th>Pattern</th>
                        <th>Module</th>
                        <th>Resolved</th>
                        <th></th>
                      </tr>
                    </thead>
                    <tbody>
                      {#each signatures as sig (sig.id)}
                        <tr>
                          <td>{sig.label}</td>
                          <td class="mono pattern-preview">{sig.pattern}</td>
                          <td>{sig.module}</td>
                          <td class="mono">
                            {#if sig.resolved_address}
                              <span class="resolved">{sig.resolved_address}</span>
                            {:else}
                              <span class="unresolved">-</span>
                            {/if}
                          </td>
                          <td class="actions-cell">
                            {#if sig.resolved_address}
                              <button
                                class="action-btn"
                                title="Add to watch list"
                                onclick={() => watchFromSignature(sig.id)}
                              >
                                <svg viewBox="0 0 20 20" fill="currentColor">
                                  <path d="M10 12a2 2 0 100-4 2 2 0 000 4z" />
                                  <path fill-rule="evenodd" d="M.458 10C1.732 5.943 5.522 3 10 3s8.268 2.943 9.542 7c-1.274 4.057-5.064 7-9.542 7S1.732 14.057.458 10zM14 10a4 4 0 11-8 0 4 4 0 018 0z" clip-rule="evenodd" />
                                </svg>
                              </button>
                            {/if}
                            <button
                              class="action-btn danger"
                              title="Remove signature"
                              onclick={() => removeSignature(sig.id)}
                            >
                              <svg viewBox="0 0 20 20" fill="currentColor">
                                <path fill-rule="evenodd" d="M9 2a1 1 0 00-.894.553L7.382 4H4a1 1 0 000 2v10a2 2 0 002 2h8a2 2 0 002-2V6a1 1 0 100-2h-3.382l-.724-1.447A1 1 0 0011 2H9zM7 8a1 1 0 012 0v6a1 1 0 11-2 0V8zm5-1a1 1 0 00-1 1v6a1 1 0 102 0V8a1 1 0 00-1-1z" clip-rule="evenodd" />
                              </svg>
                            </button>
                          </td>
                        </tr>
                      {/each}
                    </tbody>
                  </table>
                {:else}
                  <div class="empty-results">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                      <path stroke-linecap="round" stroke-linejoin="round" d="M17.593 3.322c1.1.128 1.907 1.077 1.907 2.185V21L12 17.25 4.5 21V5.507c0-1.108.806-2.057 1.907-2.185a48.507 48.507 0 0111.186 0z" />
                    </svg>
                    <p>No saved signatures</p>
                    <span>Run a pattern scan and save matches as signatures</span>
                  </div>
                {/if}
              </div>
            </div>
          </div>
        {/if}
      </div>

      <!-- Bottom Console Panel -->
      {#if consoleOpen}
        <div class="console-panel" style="height: {consoleHeight}px" class:resizing={isResizingConsole}>
          <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
          <div class="console-resize-handle" role="separator" aria-orientation="horizontal" onmousedown={startConsoleResize}></div>
          <div class="console-header">
            <!-- Script Tabs -->
            <div class="script-tabs">
              {#each scriptTabs as tab (tab.id)}
                <button
                  class="script-tab"
                  class:active={tab.id === activeTabId}
                  onclick={() => switchTab(tab.id)}
                  ondblclick={() => startRenameTab(tab.id)}
                  title={tab.name}
                >
                  {#if editingTabName === tab.id}
                    <!-- svelte-ignore a11y_autofocus -->
                    <input
                      type="text"
                      class="tab-name-input"
                      bind:value={editingTabNameValue}
                      onblur={finishRenameTab}
                      onkeydown={(e) => e.key === 'Enter' && finishRenameTab()}
                      autofocus
                    />
                  {:else}
                    <span class="tab-name">{tab.name}</span>
                    {#if tab.dirty}
                      <span class="tab-dirty">●</span>
                    {/if}
                    {#if tab.running}
                      <div class="btn-spinner-small"></div>
                    {/if}
                  {/if}
                  {#if scriptTabs.length > 1}
                    <span
                      class="tab-close"
                      role="button"
                      tabindex="0"
                      onclick={(e) => { e.stopPropagation(); closeTab(tab.id); }}
                      onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.stopPropagation(); e.preventDefault(); closeTab(tab.id); }}}
                      title="Close tab"
                    >×</span>
                  {/if}
                </button>
              {/each}
              <button class="script-tab add-tab" onclick={addNewTab} title="New script">
                <svg viewBox="0 0 20 20" fill="currentColor" style="width:14px;height:14px">
                  <path fill-rule="evenodd" d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z" clip-rule="evenodd" />
                </svg>
              </button>
            </div>

            <div class="console-actions">
              <!-- Scripts Menu -->
              <div class="scripts-menu-container">
                <button
                  class="btn btn-secondary btn-sm"
                  onclick={() => showScriptMenu = !showScriptMenu}
                  title="Scripts menu"
                >
                  <svg viewBox="0 0 20 20" fill="currentColor" style="width:14px;height:14px">
                    <path fill-rule="evenodd" d="M3 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1z" clip-rule="evenodd" />
                  </svg>
                  Scripts
                </button>
                {#if showScriptMenu}
                  <div class="scripts-dropdown">
                    <button class="dropdown-item" onclick={saveCurrentScript}>
                      <svg viewBox="0 0 20 20" fill="currentColor"><path d="M5.5 13a3.5 3.5 0 01-.369-6.98 4 4 0 117.753-1.977A4.5 4.5 0 1113.5 13H11V9.413l1.293 1.293a1 1 0 001.414-1.414l-3-3a1 1 0 00-1.414 0l-3 3a1 1 0 001.414 1.414L9 9.414V13H5.5z" /><path d="M9 13h2v5a1 1 0 11-2 0v-5z" /></svg>
                      Save Script
                      <span class="shortcut">⌘S</span>
                    </button>
                    <button class="dropdown-item" onclick={importScriptFromFile}>
                      <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zM6.293 6.707a1 1 0 010-1.414l3-3a1 1 0 011.414 0l3 3a1 1 0 01-1.414 1.414L11 5.414V13a1 1 0 11-2 0V5.414L7.707 6.707a1 1 0 01-1.414 0z" clip-rule="evenodd" /></svg>
                      Import from File
                    </button>
                    <button class="dropdown-item" onclick={exportCurrentScript}>
                      <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm3.293-7.707a1 1 0 011.414 0L9 10.586V3a1 1 0 112 0v7.586l1.293-1.293a1 1 0 111.414 1.414l-3 3a1 1 0 01-1.414 0l-3-3a1 1 0 010-1.414z" clip-rule="evenodd" /></svg>
                      Export to File
                    </button>
                    {#if savedScripts.length > 0}
                      <div class="dropdown-divider"></div>
                      <div class="dropdown-label">Saved Scripts</div>
                      {#each savedScripts as script}
                        <div class="dropdown-item-with-actions">
                          <button class="dropdown-item" onclick={() => openSavedScript(script)}>
                            <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" clip-rule="evenodd" /></svg>
                            {script.name}
                          </button>
                          <button class="dropdown-delete" onclick={() => deleteSavedScript(script.id)} title="Delete">
                            <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M9 2a1 1 0 00-.894.553L7.382 4H4a1 1 0 000 2v10a2 2 0 002 2h8a2 2 0 002-2V6a1 1 0 100-2h-3.382l-.724-1.447A1 1 0 0011 2H9zM7 8a1 1 0 012 0v6a1 1 0 11-2 0V8zm5-1a1 1 0 00-1 1v6a1 1 0 102 0V8a1 1 0 00-1-1z" clip-rule="evenodd" /></svg>
                          </button>
                        </div>
                      {/each}
                    {/if}
                  </div>
                {/if}
              </div>

              <button
                class="btn btn-sm"
                class:btn-secondary={!showScriptHelp}
                class:btn-primary={showScriptHelp}
                onclick={() => showScriptHelp = !showScriptHelp}
                title="Show API reference"
              >
                <svg viewBox="0 0 20 20" fill="currentColor" style="width:14px;height:14px">
                  <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                </svg>
                API
              </button>
              {#if scriptRunning}
                <button class="btn btn-secondary btn-sm" onclick={cancelScript} title="Stop script">
                  <svg viewBox="0 0 20 20" fill="currentColor" style="width:14px;height:14px">
                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8 7a1 1 0 00-1 1v4a1 1 0 001 1h4a1 1 0 001-1V8a1 1 0 00-1-1H8z" clip-rule="evenodd" />
                  </svg>
                  Stop
                </button>
              {:else}
                <button class="btn btn-primary btn-sm" onclick={runScript} title="Run script (Ctrl+Enter)">
                  <svg viewBox="0 0 20 20" fill="currentColor" style="width:14px;height:14px">
                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM9.555 7.168A1 1 0 008 8v4a1 1 0 001.555.832l3-2a1 1 0 000-1.664l-3-2z" clip-rule="evenodd" />
                  </svg>
                  Run
                </button>
              {/if}
              <button class="btn btn-secondary btn-sm" onclick={() => updateActiveTab({ output: [] })} title="Clear output">
                Clear
              </button>
              <button class="console-close-btn" onclick={() => consoleOpen = false} title="Close console (Esc)">
                <svg viewBox="0 0 20 20" fill="currentColor">
                  <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd" />
                </svg>
              </button>
            </div>
          </div>
          <div class="console-body">
            {#if showScriptHelp}
              <div class="script-help-panel">
                <div class="help-section">
                  <h4>Messpit Scripting</h4>
                  <p class="help-intro">Write JavaScript to automate memory operations. Scripts run in a sandboxed QuickJS environment.</p>
                </div>

                <div class="help-section">
                  <h5>Memory Operations</h5>
                  <div class="help-api">
                    <code>mem.read(address, type)</code>
                    <span>Read value from memory address</span>
                  </div>
                  <div class="help-api">
                    <code>mem.write(address, type, value)</code>
                    <span>Write value to memory address</span>
                  </div>
                  <div class="help-example">
                    <pre>// Read health value
const health = mem.read(0x12345678, "i32");
ui.print("Health: " + health);

// Set health to 999
mem.write(0x12345678, "i32", 999);</pre>
                  </div>
                </div>

                <div class="help-section">
                  <h5>Watch & Freeze</h5>
                  <div class="help-api">
                    <code>watch.add(address, type, label)</code>
                    <span>Add address to watch list</span>
                  </div>
                  <div class="help-api">
                    <code>freeze.set(address, type, value, interval)</code>
                    <span>Freeze address to value (interval in ms)</span>
                  </div>
                  <div class="help-api">
                    <code>freeze.clear(address)</code>
                    <span>Remove freeze from address</span>
                  </div>
                  <div class="help-example">
                    <pre>// Add to watch list
watch.add(0x12345678, "i32", "Player Health");

// Freeze health at 999, update every 10ms
freeze.set(0x12345678, "i32", 999, 10);</pre>
                  </div>
                </div>

                <div class="help-section">
                  <h5>Utilities</h5>
                  <div class="help-api">
                    <code>ui.print(message)</code>
                    <span>Print to console output</span>
                  </div>
                  <div class="help-api">
                    <code>ui.notify(message)</code>
                    <span>Show notification to user</span>
                  </div>
                  <div class="help-api">
                    <code>time.sleep(ms)</code>
                    <span>Pause execution (max 10000ms)</span>
                  </div>
                </div>

                <div class="help-section">
                  <h5>Value Types</h5>
                  <div class="help-types">
                    <span><code>i8</code> <code>i16</code> <code>i32</code> <code>i64</code></span>
                    <span>Signed integers</span>
                  </div>
                  <div class="help-types">
                    <span><code>u8</code> <code>u16</code> <code>u32</code> <code>u64</code></span>
                    <span>Unsigned integers</span>
                  </div>
                  <div class="help-types">
                    <span><code>f32</code> <code>f64</code></span>
                    <span>Floating point</span>
                  </div>
                </div>

                <div class="help-section">
                  <h5>Example: God Mode Script</h5>
                  <div class="help-example">
                    <pre>// Infinite health loop
const healthAddr = 0x12345678;
const maxHealth = 100;

for (let i = 0; i &lt; 10; i++) {'{'}
  mem.write(healthAddr, "i32", maxHealth);
  ui.print("Health set to " + maxHealth);
  time.sleep(1000);
{'}'}</pre>
                  </div>
                </div>
              </div>
            {:else}
              <div class="console-editor">
                <div class="editor-wrapper">
                  <pre class="syntax-highlight" aria-hidden="true">{@html highlightCode(getActiveTab()?.source ?? "")}<br/></pre>
                  <textarea
                    class="console-textarea"
                    value={getActiveTab()?.source ?? ""}
                    oninput={(e) => updateTabSource(e.currentTarget.value)}
                    placeholder="// JavaScript code... (mem.read, mem.write, ui.print, etc.)"
                    spellcheck="false"
                  ></textarea>
                </div>
              </div>
            {/if}
            <div class="console-output">
              <div class="console-output-header">Output</div>
              <div class="console-output-content" bind:this={consoleOutputEl}>
                {#if (getActiveTab()?.output ?? []).length > 0}
                  <pre>{(getActiveTab()?.output ?? []).join('\n')}</pre>
                {:else}
                  <span class="console-placeholder">Script output will appear here...</span>
                {/if}
              </div>
            </div>
          </div>
        </div>
      {/if}
  </main>
  </div>
</div>

<!-- Toast Container -->
{#if toasts.length > 0}
  <div class="toast-container">
    {#each toasts as toast (toast.id)}
      <div class="toast toast-{toast.type}">
        <div class="toast-icon">
          {#if toast.type === "success"}
            <svg viewBox="0 0 20 20" fill="currentColor">
              <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
            </svg>
          {:else if toast.type === "error"}
            <svg viewBox="0 0 20 20" fill="currentColor">
              <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
            </svg>
          {:else}
            <svg viewBox="0 0 20 20" fill="currentColor">
              <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
            </svg>
          {/if}
        </div>
        <span class="toast-message">{toast.message}</span>
      </div>
    {/each}
  </div>
{/if}

<!-- Prompt Dialog Modal -->
{#if promptDialog}
  <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
  <div class="modal-backdrop" onclick={() => promptDialog = null} role="presentation">
    <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
    <div class="modal-dialog" role="dialog" aria-modal="true" tabindex="-1" onclick={(e) => e.stopPropagation()}>
      <div class="modal-header">
        <h3>{promptDialog.title}</h3>
        <button class="modal-close" onclick={() => promptDialog = null}>&times;</button>
      </div>
      <div class="modal-body">
        <!-- svelte-ignore a11y_autofocus -->
        <input
          type="text"
          class="form-input"
          placeholder={promptDialog.placeholder}
          bind:value={promptDialog.value}
          autofocus
          onkeydown={(e) => {
            if (e.key === 'Enter' && promptDialog) {
              promptDialog.onConfirm(promptDialog.value);
              promptDialog = null;
            } else if (e.key === 'Escape') {
              promptDialog = null;
            }
          }}
        />
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" onclick={() => promptDialog = null}>Cancel</button>
        <button class="btn btn-primary" onclick={() => {
          if (promptDialog) {
            promptDialog.onConfirm(promptDialog.value);
            promptDialog = null;
          }
        }}>OK</button>
      </div>
    </div>
  </div>
{/if}

<!-- Memory Viewer Modal -->
{#if memoryViewerOpen}
  <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
  <div class="modal-backdrop" onclick={() => memoryViewerOpen = false} role="presentation">
    <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
    <div class="memory-viewer-modal" role="dialog" aria-modal="true" tabindex="-1" onclick={(e) => e.stopPropagation()}>
      <div class="modal-header">
        <h3>Memory Viewer</h3>
        <div class="memory-viewer-info">
          {#if memoryViewerRegion}
            <span class="region-badge">{memoryViewerRegion.module || "Unknown"}</span>
            <span class="mono">{getCurrentViewAddress()}</span>
          {/if}
        </div>
        <button class="modal-close" onclick={() => memoryViewerOpen = false}>&times;</button>
      </div>

      <div class="memory-viewer-toolbar">
        <div class="memory-nav">
          <button
            class="btn btn-sm btn-secondary"
            onclick={memoryViewerPrev}
            disabled={memoryViewerOffset === 0}
          >← Prev</button>
          <button
            class="btn btn-sm btn-secondary"
            onclick={memoryViewerNext}
            disabled={!memoryViewerRegion || memoryViewerOffset >= memoryViewerRegion.size - BYTES_PER_PAGE}
          >Next →</button>
        </div>
        <div class="memory-offset">
          Offset: <span class="mono">+{memoryViewerOffset.toString(16).toUpperCase()}</span>
        </div>
        <button class="btn btn-sm btn-secondary" onclick={loadMemoryBytes}>Refresh</button>
      </div>

      <div class="memory-viewer-content">
        {#if memoryViewerLoading}
          <div class="loading-state">
            <div class="loading-spinner"></div>
            <span>Reading memory...</span>
          </div>
        {:else if memoryViewerBytes.length > 0}
          <div class="hex-view">
            <div class="hex-header">
              <span class="hex-addr-header">Address</span>
              <span class="hex-bytes-header">
                {#each Array(16) as _, i}
                  <span class="hex-col-num">{i.toString(16).toUpperCase()}</span>
                {/each}
              </span>
              <span class="hex-ascii-header">ASCII</span>
            </div>
            <div class="hex-rows">
              {#each Array(Math.ceil(memoryViewerBytes.length / 16)) as _, row}
                {@const rowAddr = parseInt(memoryViewerAddress.replace("0x", ""), 16) + memoryViewerOffset + row * 16}
                {@const rowBytes = memoryViewerBytes.slice(row * 16, (row + 1) * 16)}
                <div class="hex-row">
                  <span class="hex-addr mono">{("0x" + rowAddr.toString(16).toUpperCase().padStart(16, "0"))}</span>
                  <span class="hex-bytes mono">
                    {#each rowBytes as byte, i}
                      <span class="hex-byte" class:zero={byte === 0} class:high={byte >= 128}>{formatHexByte(byte)}</span>{#if i === 7}<span class="hex-separator"></span>{/if}
                    {/each}
                    {#if rowBytes.length < 16}
                      {#each Array(16 - rowBytes.length) as _}
                        <span class="hex-byte empty">  </span>
                      {/each}
                    {/if}
                  </span>
                  <span class="hex-ascii mono">
                    {#each rowBytes as byte}
                      <span class="ascii-char" class:printable={byte >= 32 && byte <= 126}>{byteToAscii(byte)}</span>
                    {/each}
                  </span>
                </div>
              {/each}
            </div>
          </div>
        {:else}
          <div class="empty-results">
            <p>Unable to read memory at this address</p>
          </div>
        {/if}
      </div>
    </div>
  </div>
{/if}

<style>
  .app-container {
    display: flex;
    flex-direction: column;
    height: 100vh;
    overflow: hidden;
  }

  /* Top Menu Bar */
  .top-menu-bar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 16px;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--separator);
    flex-shrink: 0;
  }

  .menu-bar-left {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .app-title {
    font-size: 18px;
    font-weight: 700;
    color: var(--accent);
    letter-spacing: -0.5px;
    margin: 0;
  }

  .menu-bar-divider {
    width: 1px;
    height: 20px;
    background: var(--separator);
  }

  .project-name-container {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .project-name-btn {
    background: none;
    border: none;
    font-size: 14px;
    font-weight: 500;
    color: var(--text-primary);
    cursor: pointer;
    padding: 4px 8px;
    border-radius: var(--radius-sm);
    transition: background 0.15s;
  }

  .project-name-btn:hover {
    background: var(--bg-primary);
  }

  .project-name-input-inline {
    font-size: 14px;
    font-weight: 500;
    padding: 4px 8px;
    border: 1px solid var(--accent);
    border-radius: var(--radius-sm);
    background: white;
    outline: none;
  }

  .saved-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--success);
  }

  .unsaved-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #f59e0b;
  }

  .menu-bar-actions {
    display: flex;
    align-items: center;
    gap: 4px;
  }

  .menu-bar-btn {
    display: flex;
    align-items: center;
    gap: 4px;
    padding: 6px 10px;
    background: none;
    border: none;
    border-radius: var(--radius-sm);
    font-size: 13px;
    color: var(--text-secondary);
    cursor: pointer;
    transition: all 0.15s;
  }

  .menu-bar-btn:hover {
    background: var(--bg-primary);
    color: var(--text-primary);
  }

  .menu-bar-btn svg {
    width: 14px;
    height: 14px;
  }

  /* Main Content Area */
  .app-content {
    display: flex;
    flex: 1;
    overflow: hidden;
  }

  /* Sidebar */
  .sidebar {
    width: 280px;
    background: var(--bg-secondary);
    border-right: 1px solid var(--separator);
    display: flex;
    flex-direction: column;
  }

  .search-container {
    padding: 12px 16px;
    position: relative;
  }

  .search-icon {
    position: absolute;
    left: 28px;
    top: 50%;
    transform: translateY(-50%);
    width: 16px;
    height: 16px;
    color: var(--text-tertiary);
  }

  .search-input {
    width: 100%;
    padding: 10px 12px 10px 36px;
    border: none;
    background: var(--bg-primary);
    border-radius: var(--radius-md);
    font-size: 14px;
    color: var(--text-primary);
    outline: none;
    transition: box-shadow 0.2s;
  }

  .search-input::placeholder {
    color: var(--text-tertiary);
  }

  .search-input:focus {
    box-shadow: 0 0 0 3px var(--accent-light);
  }

  .process-list-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 16px;
  }

  .filter-checkbox {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 4px 16px 8px;
    font-size: 11px;
    color: var(--text-secondary);
    cursor: pointer;
    user-select: none;
  }

  .filter-checkbox input[type="checkbox"] {
    width: 14px;
    height: 14px;
    accent-color: var(--accent);
    cursor: pointer;
  }

  .filter-checkbox:hover {
    color: var(--text-primary);
  }

  .section-label {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .icon-button {
    width: 28px;
    height: 28px;
    border: none;
    background: transparent;
    border-radius: var(--radius-sm);
    color: var(--text-secondary);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all 0.15s;
  }

  .icon-button:hover:not(:disabled) {
    background: var(--bg-primary);
    color: var(--accent);
  }

  .icon-button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .refresh-icon {
    width: 16px;
    height: 16px;
  }

  .refresh-icon.spinning {
    animation: spin 1s linear infinite;
  }

  @keyframes spin {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
  }

  .process-list {
    flex: 1;
    overflow-y: auto;
    padding: 0 8px;
  }

  .process-item {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 12px;
    border: none;
    background: transparent;
    border-radius: var(--radius-md);
    cursor: pointer;
    text-align: left;
    transition: all 0.15s;
  }

  .process-item:hover {
    background: var(--bg-primary);
  }

  .process-item.selected {
    background: var(--accent);
  }

  .process-item.selected .process-name,
  .process-item.selected .process-details,
  .process-item.selected .process-pid,
  .process-item.selected .process-icon {
    color: white;
  }

  .process-icon {
    width: 32px;
    height: 32px;
    border-radius: var(--radius-sm);
    background: var(--bg-primary);
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--text-secondary);
    flex-shrink: 0;
  }

  .process-item.selected .process-icon {
    background: rgba(255, 255, 255, 0.2);
  }

  .process-icon svg {
    width: 16px;
    height: 16px;
  }

  .process-info {
    flex: 1;
    min-width: 0;
  }

  .process-name {
    display: block;
    font-size: 14px;
    font-weight: 500;
    color: var(--text-primary);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .process-details {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 12px;
    color: var(--text-secondary);
  }

  .process-pid {
    flex-shrink: 0;
  }

  .process-path {
    color: var(--text-tertiary);
    font-size: 11px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 120px;
  }

  .process-item.selected .process-path {
    color: rgba(255, 255, 255, 0.7);
  }

  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 40px 20px;
    color: var(--text-secondary);
    font-size: 14px;
    gap: 12px;
  }

  .loading-spinner {
    width: 24px;
    height: 24px;
    border: 2px solid var(--separator);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }

  .show-more-btn {
    width: 100%;
    padding: 8px 16px;
    background: var(--surface);
    border: none;
    border-top: 1px solid var(--separator);
    color: var(--primary);
    font-size: 12px;
    cursor: pointer;
    text-align: center;
  }

  .show-more-btn:hover {
    background: var(--hover);
  }

  .sidebar-footer {
    padding: 12px 16px;
    border-top: 1px solid var(--separator);
    font-size: 12px;
    color: var(--text-tertiary);
  }

  /* Main Content */
  .main-content {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    background: var(--bg-primary);
  }

  .error-banner {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 12px 16px;
    background: #fef2f2;
    border-bottom: 1px solid #fecaca;
    color: var(--danger);
    font-size: 14px;
  }

  .error-banner svg {
    width: 18px;
    height: 18px;
    flex-shrink: 0;
  }

  .error-banner span {
    flex: 1;
  }

  .dismiss-btn {
    width: 24px;
    height: 24px;
    border: none;
    background: transparent;
    color: var(--danger);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: var(--radius-sm);
  }

  .dismiss-btn:hover {
    background: rgba(255, 59, 48, 0.1);
  }

  .dismiss-btn svg {
    width: 16px;
    height: 16px;
  }

  .connected-header {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 16px 20px;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--separator);
  }

  .connection-badge {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 4px 10px;
    background: #dcfce7;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 500;
    color: #166534;
  }

  .pulse-dot {
    width: 8px;
    height: 8px;
    background: var(--success);
    border-radius: 50%;
    animation: pulse 2s ease-in-out infinite;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }

  .connected-info {
    flex: 1;
  }

  .connected-info h2 {
    font-size: 16px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .connected-info p {
    font-size: 13px;
    color: var(--text-secondary);
  }

  .disconnected-header {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 20px;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--separator);
  }

  .disconnected-badge {
    padding: 4px 10px;
    background: #f3f4f6;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 500;
    color: var(--text-secondary);
  }

  .disconnected-hint {
    font-size: 13px;
    color: var(--text-tertiary);
  }

  .btn {
    padding: 8px 16px;
    border: none;
    border-radius: var(--radius-sm);
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.15s;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
  }

  .btn-sm {
    padding: 4px 10px;
    font-size: 12px;
  }

  .btn-primary {
    background: var(--accent);
    color: white;
  }

  .btn-primary:hover:not(:disabled) {
    background: #0066d6;
  }

  .btn-primary:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .btn-secondary {
    background: var(--bg-primary);
    color: var(--text-primary);
  }

  .btn-secondary:hover {
    background: var(--bg-tertiary);
  }

  .btn-spinner {
    width: 14px;
    height: 14px;
    border: 2px solid rgba(255, 255, 255, 0.3);
    border-top-color: white;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }

  /* Tab Bar */
  .tab-bar {
    display: flex;
    padding: 0 20px;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--separator);
  }

  .tab-item {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 14px 16px;
    border: none;
    background: transparent;
    color: var(--text-secondary);
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    border-bottom: 2px solid transparent;
    margin-bottom: -1px;
    transition: all 0.15s;
  }

  .tab-item svg {
    width: 16px;
    height: 16px;
  }

  .tab-item:hover {
    color: var(--text-primary);
  }

  .tab-item.active {
    color: var(--accent);
    border-bottom-color: var(--accent);
  }

  .badge {
    padding: 2px 6px;
    background: var(--bg-primary);
    border-radius: 10px;
    font-size: 11px;
    font-weight: 600;
    color: var(--text-secondary);
  }

  .tab-item.active .badge {
    background: var(--accent-light);
    color: var(--accent);
  }

  /* Tab Content */
  .tab-content {
    flex: 1;
    overflow: hidden;
    padding: 20px;
  }

  .scan-panel, .watch-panel, .regions-panel {
    display: flex;
    flex-direction: column;
    gap: 16px;
    height: 100%;
  }

  .card {
    background: var(--bg-secondary);
    border-radius: var(--radius-lg);
    box-shadow: var(--shadow-sm);
    overflow: hidden;
    display: flex;
    flex-direction: column;
  }

  .card.flex-1 {
    flex: 1;
    min-height: 0;
  }

  .card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 16px 20px;
    border-bottom: 1px solid var(--separator);
  }

  .card-header h3 {
    font-size: 15px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .results-count {
    font-size: 13px;
    color: var(--text-secondary);
  }

  .card-body {
    padding: 20px;
  }

  .form-row {
    display: flex;
    gap: 12px;
    align-items: flex-end;
  }

  .form-group {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .form-group.flex-1 {
    flex: 1;
  }

  .form-label {
    font-size: 13px;
    font-weight: 500;
    color: var(--text-secondary);
  }

  .form-input, .form-select {
    padding: 10px 12px;
    border: 1px solid var(--separator);
    border-radius: var(--radius-sm);
    font-size: 14px;
    color: var(--text-primary);
    background: var(--bg-secondary);
    outline: none;
    transition: all 0.15s;
  }

  .form-input:focus, .form-select:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-light);
  }

  .form-select {
    min-width: 110px;
    cursor: pointer;
  }

  /* Refine section */
  .refine-section {
    display: flex;
    flex-direction: column;
  }

  .refine-modes {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
  }

  .refine-btn {
    padding: 8px 14px;
    border: 1px solid var(--separator);
    border-radius: var(--radius-sm);
    background: var(--bg-secondary);
    color: var(--text-secondary);
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.15s;
  }

  .refine-btn:hover {
    border-color: var(--accent);
    color: var(--accent);
  }

  .refine-btn.active {
    background: var(--accent);
    border-color: var(--accent);
    color: white;
  }

  .mt-12 {
    margin-top: 12px;
  }

  .flex-1 {
    flex: 1;
  }

  /* Results Table */
  .results-table-container, .regions-table-container {
    flex: 1;
    overflow: auto;
  }

  .results-table {
    width: 100%;
    border-collapse: collapse;
  }

  .results-table th {
    position: sticky;
    top: 0;
    background: var(--bg-secondary);
    padding: 12px 20px;
    text-align: left;
    font-size: 12px;
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border-bottom: 1px solid var(--separator);
  }

  .results-table td {
    padding: 12px 20px;
    font-size: 14px;
    border-bottom: 1px solid var(--separator);
  }

  .results-table tr:hover td {
    background: var(--bg-primary);
  }

  .results-table tr.frozen td {
    background: #dcfce7;
  }

  .mono {
    font-family: "SF Mono", "Menlo", monospace;
    font-size: 13px;
    color: var(--accent);
  }

  .value-cell {
    font-weight: 500;
    color: var(--success);
  }

  .label-cell {
    font-weight: 500;
    color: var(--text-primary);
  }

  .type-cell {
    color: var(--text-secondary);
    font-size: 12px;
    text-transform: uppercase;
  }

  .actions-cell {
    width: 80px;
    text-align: right;
  }

  .action-btn {
    width: 28px;
    height: 28px;
    border: none;
    background: transparent;
    color: var(--text-tertiary);
    border-radius: var(--radius-sm);
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    transition: all 0.15s;
    margin-left: 4px;
  }

  .action-btn:hover {
    background: var(--accent-light);
    color: var(--accent);
  }

  .action-btn.active {
    background: var(--accent);
    color: white;
  }

  .action-btn.delete:hover {
    background: #fee2e2;
    color: var(--danger);
  }

  .action-btn svg {
    width: 16px;
    height: 16px;
  }

  .perm-badges {
    display: flex;
    gap: 4px;
  }

  .perm-badge {
    width: 22px;
    height: 22px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
  }

  .perm-badge.read {
    background: #dbeafe;
    color: #1d4ed8;
  }

  .perm-badge.write {
    background: #dcfce7;
    color: #166534;
  }

  .perm-badge.exec {
    background: #fef3c7;
    color: #92400e;
  }

  /* Regions toolbar */
  .regions-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
  }

  .regions-filters {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .toggle-label {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    cursor: pointer;
    white-space: nowrap;
  }

  .toggle-label input[type="checkbox"] {
    width: 14px;
    height: 14px;
    cursor: pointer;
  }

  .form-input-sm {
    padding: 4px 8px;
    font-size: 11px;
    height: 26px;
  }

  .regions-hint {
    font-size: 11px;
    color: var(--text-secondary);
    opacity: 0.7;
  }

  .btn-clear {
    background: none;
    border: none;
    color: var(--text-secondary);
    cursor: pointer;
    font-size: 16px;
    padding: 0 4px;
    line-height: 1;
  }

  .btn-clear:hover {
    color: var(--text);
  }

  /* Regions table */
  .regions-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 11px;
  }

  .regions-table thead {
    position: sticky;
    top: 0;
    background: var(--card-bg);
    z-index: 1;
  }

  .regions-table th {
    padding: 6px 8px;
    text-align: left;
    font-weight: 600;
    color: var(--text-secondary);
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }

  .regions-table th.sortable {
    cursor: pointer;
    user-select: none;
    transition: background 0.15s, color 0.15s;
  }

  .regions-table th.sortable:hover {
    background: var(--hover-bg);
    color: var(--text);
  }

  .regions-table th.sorted {
    color: var(--primary);
  }

  .regions-table td {
    padding: 4px 8px;
    border-bottom: 1px solid var(--border);
    vertical-align: middle;
  }

  .regions-table tbody tr:hover {
    background: var(--hover-bg);
  }

  .regions-table tbody tr.non-writable {
    opacity: 0.4;
  }

  .regions-table tbody tr.non-writable:hover {
    opacity: 0.7;
  }

  .regions-table .col-addr {
    white-space: nowrap;
  }

  .regions-table .col-size {
    text-align: right;
    white-space: nowrap;
    color: var(--text-secondary);
  }

  .regions-table .col-perms {
    text-align: center;
  }

  .regions-table .col-module {
    max-width: 140px;
  }

  /* Pagination */
  .pagination {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 12px 16px;
    background: var(--bg-secondary);
    border-top: 1px solid var(--separator);
  }

  .pagination-btn {
    min-width: 32px;
    height: 32px;
    padding: 0 8px;
    border: 1px solid var(--border);
    background: var(--bg-primary);
    color: var(--text-primary);
    border-radius: var(--radius-sm);
    cursor: pointer;
    font-size: 14px;
    font-weight: 500;
    transition: all 0.15s;
  }

  .pagination-btn:hover:not(:disabled) {
    background: var(--bg-tertiary);
    border-color: var(--accent);
  }

  .pagination-btn:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }

  .pagination-info {
    font-size: 13px;
    color: var(--text-secondary);
    padding: 0 12px;
  }

  .pagination-range {
    color: var(--text-tertiary);
    font-size: 12px;
    margin-left: 4px;
  }

  .addr-btn {
    background: none;
    border: none;
    padding: 2px 4px;
    margin: -2px -4px;
    border-radius: 3px;
    cursor: pointer;
    color: inherit;
    font: inherit;
  }

  .addr-btn:hover {
    background: var(--border);
  }

  .region-perms {
    display: inline-flex;
    font-weight: 600;
    font-family: var(--font-mono);
  }

  .region-perms .perm {
    width: 14px;
    text-align: center;
    color: var(--text-secondary);
    opacity: 0.3;
  }

  .region-perms .perm.active {
    opacity: 1;
  }

  .region-perms .perm.active:nth-child(1) { color: #3b82f6; }
  .region-perms .perm.active:nth-child(2) { color: #22c55e; }
  .region-perms .perm.active:nth-child(3) { color: #f59e0b; }

  .region-module {
    background: var(--border);
    padding: 1px 6px;
    border-radius: 3px;
    font-size: 10px;
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    border: none;
    cursor: pointer;
    color: var(--text);
    display: block;
  }

  .region-module:hover {
    background: var(--primary);
    color: white;
  }

  .no-module {
    color: var(--text-secondary);
    opacity: 0.5;
  }

  .empty-results, .loading-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 60px 20px;
    color: var(--text-secondary);
    text-align: center;
  }

  .empty-results svg {
    width: 48px;
    height: 48px;
    margin-bottom: 16px;
    opacity: 0.3;
  }

  .empty-results p {
    font-size: 15px;
    font-weight: 500;
    color: var(--text-primary);
    margin-bottom: 4px;
  }

  .empty-results span {
    font-size: 13px;
  }

  .loading-state {
    gap: 12px;
  }

  /* Requires Process State */
  .requires-process {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 60px 20px;
    text-align: center;
    color: var(--text-secondary);
  }

  .requires-process svg {
    width: 64px;
    height: 64px;
    margin-bottom: 20px;
    opacity: 0.3;
  }

  .requires-process h3 {
    font-size: 18px;
    font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 8px;
  }

  .requires-process p {
    font-size: 14px;
    color: var(--text-secondary);
  }

  .running-indicator {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--accent);
  }

  .btn-spinner-small {
    width: 12px;
    height: 12px;
    border: 2px solid var(--separator);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }

  /* Wizard Styles */
  .wizard-container {
    display: flex;
    flex-direction: column;
    gap: 20px;
    height: 100%;
  }

  .wizard-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 16px 20px;
    background: var(--bg-secondary);
    border-radius: var(--radius-lg);
    box-shadow: var(--shadow-sm);
  }

  .wizard-title {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .wizard-title h3 {
    font-size: 18px;
    font-weight: 600;
    color: var(--text-primary);
    margin: 0;
  }

  .wizard-step-indicator {
    font-size: 13px;
    color: var(--text-secondary);
  }

  .wizard-progress {
    height: 4px;
    background: var(--separator);
    border-radius: 2px;
    overflow: hidden;
  }

  .wizard-progress-bar {
    height: 100%;
    background: var(--accent);
    border-radius: 2px;
    transition: width 0.3s ease;
  }

  .wizard-content {
    flex: 1;
    display: flex;
    flex-direction: column;
    background: var(--bg-secondary);
    border-radius: var(--radius-lg);
    box-shadow: var(--shadow-sm);
    padding: 24px;
    min-height: 0;
    overflow-y: auto;
  }

  .wizard-step {
    display: flex;
    flex-direction: column;
    gap: 20px;
  }

  .wizard-step-header {
    display: flex;
    gap: 16px;
    align-items: flex-start;
  }

  .wizard-step-number {
    width: 36px;
    height: 36px;
    background: var(--accent);
    color: white;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 16px;
    font-weight: 600;
    flex-shrink: 0;
  }

  .wizard-step-header h4 {
    font-size: 18px;
    font-weight: 600;
    color: var(--text-primary);
    margin: 0;
  }

  .wizard-step-header p {
    font-size: 14px;
    color: var(--text-secondary);
    margin: 4px 0 0;
  }

  .wizard-form {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .wizard-tip {
    padding: 12px 16px;
    background: #f0f9ff;
    border-radius: var(--radius-md);
    font-size: 13px;
    color: #0369a1;
    border-left: 3px solid var(--accent);
  }

  .wizard-instruction {
    padding: 16px 20px;
    background: #fef3c7;
    border-radius: var(--radius-md);
    font-size: 14px;
    color: #92400e;
    text-align: center;
    border-left: 3px solid #f59e0b;
  }

  .wizard-refine-options {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .refine-option {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 16px 20px;
    background: var(--bg-primary);
    border-radius: var(--radius-md);
    cursor: pointer;
    transition: all 0.15s;
    border: 1px solid transparent;
  }

  .refine-option:hover {
    border-color: var(--accent);
    background: var(--accent-light);
  }

  .refine-option.exact-option {
    cursor: default;
    flex-wrap: wrap;
  }

  .refine-option.exact-option:hover {
    border-color: transparent;
    background: var(--bg-primary);
  }

  .refine-option-icon {
    width: 40px;
    height: 40px;
    background: var(--bg-secondary);
    border-radius: var(--radius-sm);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 20px;
    font-weight: 600;
    color: var(--accent);
    flex-shrink: 0;
  }

  .refine-option-text {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .refine-option-text strong {
    font-size: 14px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .refine-option-text span {
    font-size: 13px;
    color: var(--text-secondary);
  }

  .mt-8 {
    margin-top: 8px;
  }

  .wizard-results {
    display: flex;
    flex-direction: column;
    gap: 8px;
    max-height: 300px;
    overflow-y: auto;
  }

  .wizard-result-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 16px;
    background: var(--bg-primary);
    border-radius: var(--radius-md);
    border: 1px solid var(--separator);
    cursor: pointer;
    transition: all 0.15s;
  }

  .wizard-result-item:hover {
    border-color: var(--accent);
    background: var(--accent-light);
  }

  .wizard-result-info {
    display: flex;
    gap: 16px;
    align-items: center;
  }

  .wizard-result-value {
    font-weight: 600;
    color: var(--success);
  }

  .wizard-actions {
    display: flex;
    gap: 12px;
    margin-top: 8px;
  }

  .wizard-success {
    text-align: center;
    padding: 40px 20px;
  }

  .wizard-success-icon {
    width: 64px;
    height: 64px;
    background: #dcfce7;
    color: var(--success);
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 32px;
    margin: 0 auto 16px;
  }

  .wizard-success h4 {
    font-size: 22px;
    font-weight: 600;
    color: var(--text-primary);
    margin: 0 0 8px;
  }

  .wizard-success p {
    font-size: 15px;
    color: var(--text-secondary);
    margin: 0;
  }

  .wizard-next-steps {
    margin: 24px 0;
    padding: 16px 20px;
    background: var(--bg-primary);
    border-radius: var(--radius-md);
    text-align: left;
  }

  .wizard-next-steps p {
    margin: 0 0 12px;
    font-size: 14px;
  }

  .wizard-next-steps ul {
    margin: 0;
    padding-left: 20px;
  }

  .wizard-next-steps li {
    font-size: 13px;
    color: var(--text-secondary);
    margin-bottom: 8px;
  }

  .wizard-next-steps li:last-child {
    margin-bottom: 0;
  }

  .wizard-history {
    background: var(--bg-secondary);
    border-radius: var(--radius-lg);
    box-shadow: var(--shadow-sm);
    padding: 16px 20px;
  }

  .wizard-history h5 {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin: 0 0 12px;
  }

  .wizard-history-item {
    font-size: 12px;
    color: var(--text-secondary);
    padding: 6px 0;
    border-bottom: 1px solid var(--separator);
  }

  .wizard-history-item:last-child {
    border-bottom: none;
  }

  .btn-lg {
    padding: 12px 24px;
    font-size: 15px;
  }

  .btn-accent {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    border: none;
  }

  .btn-accent:hover {
    background: linear-gradient(135deg, #5a67d8 0%, #6b46c1 100%);
  }

  .header-actions {
    display: flex;
    gap: 8px;
  }

  /* Patterns Panel Styles */
  .patterns-panel {
    display: flex;
    flex-direction: column;
    gap: 16px;
    height: 100%;
  }

  .pattern-tip {
    margin-top: 12px;
    padding: 8px 12px;
    background: #f0f9ff;
    border-radius: var(--radius-sm);
    font-size: 12px;
    color: var(--text-secondary);
  }

  .pattern-tip code {
    background: var(--bg-secondary);
    padding: 2px 6px;
    border-radius: 3px;
    font-family: 'SF Mono', Monaco, monospace;
    color: var(--accent);
  }

  .pattern-preview {
    max-width: 200px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: 12px;
  }

  .signature-form {
    background: var(--bg-primary);
    border-bottom: 1px solid var(--separator);
  }

  .form-actions {
    display: flex;
    justify-content: flex-end;
    margin-top: 12px;
  }

  .resolved {
    color: var(--success);
  }

  .unresolved {
    color: var(--text-tertiary);
  }

  .action-btn.danger {
    color: var(--danger);
  }

  .action-btn.danger:hover {
    background: #fee2e2;
  }

  /* Manual Entry and Watch Editing */
  .manual-entry-form {
    background: var(--bg-primary);
    border-bottom: 1px solid var(--separator);
  }

  .header-right {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .offline-badge {
    background: #fef3c7;
    color: #92400e;
    padding: 2px 8px;
    border-radius: var(--radius-sm);
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
  }

  .value-edit-container {
    display: flex;
    gap: 6px;
    align-items: center;
  }

  .value-edit-input {
    padding: 4px 8px;
    border: 1px solid var(--accent);
    border-radius: var(--radius-sm);
    font-size: 13px;
    font-family: 'SF Mono', Monaco, monospace;
    width: 120px;
    background: white;
  }

  .value-edit-input:focus {
    outline: none;
    box-shadow: 0 0 0 2px var(--accent-light);
  }

  .value-display {
    font-weight: 500;
  }

  .value-display.no-value {
    color: var(--text-tertiary);
  }

  tr.editing {
    background: var(--accent-light);
  }

  tr.editing td {
    padding-top: 8px;
    padding-bottom: 8px;
  }

  .action-btn:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }

  .action-btn:disabled:hover {
    background: transparent;
  }

  /* Tab bar spacer */
  .tab-spacer {
    flex: 1;
  }

  .console-toggle {
    margin-left: auto;
  }

  /* Bottom Console Panel */
  .console-panel {
    display: flex;
    flex-direction: column;
    background: var(--bg-secondary);
    border-top: 1px solid var(--separator);
    flex-shrink: 0;
    min-height: 150px;
    max-height: 50vh;
  }

  .console-resize-handle {
    height: 4px;
    background: var(--separator);
    cursor: ns-resize;
    transition: background 0.15s;
  }

  .console-resize-handle:hover {
    background: var(--accent);
  }

  .console-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 12px;
    border-bottom: 1px solid var(--separator);
    background: var(--bg-primary);
  }

  .console-title {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .console-title svg {
    width: 16px;
    height: 16px;
    color: var(--accent);
  }

  .console-running-badge {
    display: flex;
    align-items: center;
    gap: 6px;
    background: var(--accent-light);
    color: var(--accent);
    padding: 2px 8px;
    border-radius: var(--radius-sm);
    font-size: 11px;
    font-weight: 500;
  }

  .console-actions {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .console-close-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 24px;
    height: 24px;
    background: none;
    border: none;
    border-radius: var(--radius-sm);
    color: var(--text-tertiary);
    cursor: pointer;
    transition: all 0.15s;
  }

  .console-close-btn:hover {
    background: var(--bg-secondary);
    color: var(--text-primary);
  }

  .console-close-btn svg {
    width: 14px;
    height: 14px;
  }

  .console-body {
    display: flex;
    flex: 1;
    overflow: hidden;
  }

  .console-editor {
    flex: 1;
    display: flex;
    flex-direction: column;
    border-right: 1px solid var(--separator);
  }

  .console-textarea {
    flex: 1;
    width: 100%;
    padding: 12px;
    border: none;
    background: var(--bg-secondary);
    color: var(--text-primary);
    font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
    font-size: 12px;
    line-height: 1.5;
    resize: none;
    outline: none;
  }

  .console-textarea::placeholder {
    color: var(--text-tertiary);
  }

  .console-output {
    flex: 1;
    display: flex;
    flex-direction: column;
    background: #1e1e1e;
    min-width: 300px;
  }

  .console-output-header {
    padding: 6px 12px;
    font-size: 11px;
    font-weight: 600;
    color: #888;
    text-transform: uppercase;
    border-bottom: 1px solid #333;
  }

  .console-output-content {
    flex: 1;
    padding: 12px;
    overflow-y: auto;
    font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
    font-size: 12px;
    line-height: 1.5;
  }

  .console-output-content pre {
    margin: 0;
    color: #d4d4d4;
    white-space: pre-wrap;
    word-wrap: break-word;
  }

  .console-placeholder {
    color: #666;
    font-style: italic;
  }

  /* Console resizing state */
  .console-panel.resizing {
    user-select: none;
  }

  .console-panel.resizing .console-resize-handle {
    background: var(--accent);
  }

  .console-shortcut {
    font-size: 11px;
    color: var(--text-tertiary);
    background: var(--bg-secondary);
    padding: 2px 6px;
    border-radius: var(--radius-sm);
    font-family: system-ui;
  }

  /* Syntax highlighting editor */
  .editor-wrapper {
    position: relative;
    flex: 1;
    display: flex;
    overflow: hidden;
  }

  .syntax-highlight {
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    margin: 0;
    padding: 12px;
    font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
    font-size: 12px;
    line-height: 1.5;
    white-space: pre-wrap;
    word-wrap: break-word;
    color: var(--text-primary);
    pointer-events: none;
    overflow: auto;
    background: var(--bg-secondary);
  }

  .editor-wrapper .console-textarea {
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: transparent;
    color: transparent;
    caret-color: var(--text-primary);
    z-index: 1;
  }

  /* Syntax highlighting colors */
  .syntax-highlight :global(.hl-keyword) {
    color: #c678dd;
  }

  .syntax-highlight :global(.hl-string) {
    color: #98c379;
  }

  .syntax-highlight :global(.hl-comment) {
    color: #5c6370;
    font-style: italic;
  }

  .syntax-highlight :global(.hl-number) {
    color: #d19a66;
  }

  .syntax-highlight :global(.hl-function) {
    color: #61afef;
  }

  /* Script Help Panel */
  .script-help-panel {
    flex: 1;
    overflow-y: auto;
    padding: 16px 20px;
    background: var(--bg-secondary);
    border-right: 1px solid var(--separator);
  }

  .help-section {
    margin-bottom: 20px;
  }

  .help-section:last-child {
    margin-bottom: 0;
  }

  .help-section h4 {
    font-size: 16px;
    font-weight: 600;
    color: var(--text-primary);
    margin: 0 0 8px;
  }

  .help-section h5 {
    font-size: 13px;
    font-weight: 600;
    color: var(--accent);
    margin: 0 0 10px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .help-intro {
    font-size: 13px;
    color: var(--text-secondary);
    margin: 0;
    line-height: 1.5;
  }

  .help-api {
    display: flex;
    flex-direction: column;
    gap: 2px;
    margin-bottom: 8px;
    padding: 8px 10px;
    background: var(--bg-primary);
    border-radius: var(--radius-sm);
  }

  .help-api code {
    font-family: 'SF Mono', Monaco, monospace;
    font-size: 12px;
    color: var(--accent);
    font-weight: 500;
  }

  .help-api span {
    font-size: 12px;
    color: var(--text-secondary);
  }

  .help-example {
    margin-top: 8px;
  }

  .help-example pre {
    margin: 0;
    padding: 10px 12px;
    background: #1e1e1e;
    border-radius: var(--radius-sm);
    font-family: 'SF Mono', Monaco, monospace;
    font-size: 11px;
    line-height: 1.5;
    color: #d4d4d4;
    overflow-x: auto;
  }

  .help-types {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 6px 10px;
    background: var(--bg-primary);
    border-radius: var(--radius-sm);
    margin-bottom: 6px;
  }

  .help-types code {
    font-family: 'SF Mono', Monaco, monospace;
    font-size: 11px;
    background: var(--bg-secondary);
    padding: 2px 6px;
    border-radius: 3px;
    color: var(--accent);
    margin-right: 4px;
  }

  .help-types > span:last-child {
    font-size: 12px;
    color: var(--text-secondary);
  }

  /* Toast notifications */
  .toast-container {
    position: fixed;
    bottom: 24px;
    right: 24px;
    z-index: 9999;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .toast {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 12px 16px;
    background: var(--bg-secondary);
    border: 1px solid var(--separator);
    border-radius: var(--radius-md);
    box-shadow: var(--shadow-lg);
    animation: toast-slide-in 0.3s ease-out;
    min-width: 200px;
    max-width: 360px;
  }

  @keyframes toast-slide-in {
    from {
      opacity: 0;
      transform: translateX(100%);
    }
    to {
      opacity: 1;
      transform: translateX(0);
    }
  }

  .toast-icon {
    flex-shrink: 0;
    width: 20px;
    height: 20px;
  }

  .toast-icon svg {
    width: 100%;
    height: 100%;
  }

  .toast-success .toast-icon {
    color: var(--success);
  }

  .toast-error .toast-icon {
    color: var(--danger);
  }

  .toast-info .toast-icon {
    color: var(--accent);
  }

  .toast-message {
    font-size: 14px;
    color: var(--text-primary);
  }

  /* Process pinning */
  .process-item-wrapper {
    display: flex;
    align-items: stretch;
    position: relative;
  }

  .process-item-wrapper .process-item {
    flex: 1;
    border-radius: var(--radius-md) 0 0 var(--radius-md);
  }

  .process-item-wrapper.pinned {
    background: linear-gradient(90deg, rgba(255, 149, 0, 0.1), transparent);
    border-radius: var(--radius-md);
  }

  .process-item-wrapper.pinned .process-item {
    background: transparent;
  }

  .pin-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    background: transparent;
    border: none;
    cursor: pointer;
    color: var(--text-tertiary);
    transition: color 0.15s, transform 0.15s;
    border-radius: 0 var(--radius-md) var(--radius-md) 0;
    opacity: 0;
  }

  .process-item-wrapper:hover .pin-btn {
    opacity: 1;
  }

  .pin-btn:hover {
    color: var(--warning);
    transform: scale(1.1);
  }

  .pin-btn.pinned {
    opacity: 1;
    color: var(--warning);
  }

  .pin-btn svg {
    width: 14px;
    height: 14px;
  }

  /* Value change highlighting */
  .value-changed {
    animation: value-flash 1.5s ease-out;
  }

  @keyframes value-flash {
    0% {
      background-color: rgba(34, 197, 94, 0.3);
    }
    100% {
      background-color: transparent;
    }
  }

  .value-display.changed {
    color: var(--success);
    font-weight: 600;
  }

  /* Script Tabs */
  .script-tabs {
    display: flex;
    align-items: center;
    gap: 2px;
    flex: 1;
    min-width: 0;
    overflow-x: auto;
    padding-right: 12px;
  }

  .script-tabs::-webkit-scrollbar {
    height: 4px;
  }

  .script-tabs::-webkit-scrollbar-track {
    background: transparent;
  }

  .script-tabs::-webkit-scrollbar-thumb {
    background: var(--separator);
    border-radius: 2px;
  }

  .script-tab {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 6px 12px;
    background: transparent;
    border: none;
    border-radius: var(--radius-sm) var(--radius-sm) 0 0;
    font-size: 12px;
    color: var(--text-secondary);
    cursor: pointer;
    white-space: nowrap;
    transition: all 0.15s;
    max-width: 150px;
  }

  .script-tab:hover {
    background: var(--bg-secondary);
    color: var(--text-primary);
  }

  .script-tab.active {
    background: var(--bg-secondary);
    color: var(--text-primary);
    font-weight: 500;
  }

  .script-tab.add-tab {
    padding: 6px 8px;
    max-width: none;
  }

  .script-tab.add-tab:hover {
    color: var(--accent);
  }

  .tab-name {
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .tab-name-input {
    width: 80px;
    padding: 2px 4px;
    border: 1px solid var(--accent);
    border-radius: 3px;
    font-size: 12px;
    background: white;
    outline: none;
  }

  .tab-dirty {
    color: var(--warning);
    font-size: 10px;
  }

  .tab-close {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 16px;
    height: 16px;
    padding: 0;
    border: none;
    background: transparent;
    color: var(--text-tertiary);
    cursor: pointer;
    border-radius: 3px;
    font-size: 14px;
    line-height: 1;
    opacity: 0;
    transition: all 0.15s;
  }

  .script-tab:hover .tab-close {
    opacity: 1;
  }

  .tab-close:hover {
    background: var(--bg-primary);
    color: var(--danger);
  }

  /* Scripts Dropdown Menu */
  .scripts-menu-container {
    position: relative;
  }

  .scripts-dropdown {
    position: absolute;
    top: 100%;
    left: 0;
    margin-top: 4px;
    min-width: 200px;
    background: var(--bg-secondary);
    border: 1px solid var(--separator);
    border-radius: var(--radius-md);
    box-shadow: var(--shadow-lg);
    z-index: 100;
    padding: 4px 0;
  }

  .dropdown-item {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    padding: 8px 12px;
    border: none;
    background: none;
    font-size: 13px;
    color: var(--text-primary);
    cursor: pointer;
    text-align: left;
    transition: background 0.15s;
  }

  .dropdown-item:hover {
    background: var(--bg-primary);
  }

  .dropdown-item svg {
    width: 16px;
    height: 16px;
    color: var(--text-secondary);
    flex-shrink: 0;
  }

  .dropdown-item .shortcut {
    margin-left: auto;
    font-size: 11px;
    color: var(--text-tertiary);
  }

  .dropdown-divider {
    height: 1px;
    background: var(--separator);
    margin: 4px 0;
  }

  .dropdown-label {
    padding: 6px 12px 4px;
    font-size: 11px;
    font-weight: 600;
    color: var(--text-tertiary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .dropdown-item-with-actions {
    display: flex;
    align-items: stretch;
  }

  .dropdown-item-with-actions .dropdown-item {
    flex: 1;
  }

  .dropdown-delete {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    border: none;
    background: none;
    color: var(--text-tertiary);
    cursor: pointer;
    transition: all 0.15s;
  }

  .dropdown-delete:hover {
    background: #fee2e2;
    color: var(--danger);
  }

  .dropdown-delete svg {
    width: 14px;
    height: 14px;
  }

  /* Modal Dialog */
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.75);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
    backdrop-filter: blur(2px);
  }

  .modal-dialog {
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    min-width: 320px;
    max-width: 90vw;
    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
  }

  .modal-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
  }

  .modal-header h3 {
    margin: 0;
    font-size: 14px;
    font-weight: 600;
  }

  .modal-close {
    background: none;
    border: none;
    font-size: 20px;
    color: var(--text-secondary);
    cursor: pointer;
    padding: 0;
    line-height: 1;
  }

  .modal-close:hover {
    color: var(--text);
  }

  .modal-body {
    padding: 16px;
  }

  .modal-body .form-input {
    width: 100%;
  }

  .modal-footer {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    padding: 12px 16px;
    border-top: 1px solid var(--border);
  }

  /* View button in regions table */
  .btn-view {
    padding: 3px 10px;
    font-size: 11px;
    font-weight: 500;
    background: #3b82f6;
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    transition: background 0.15s;
  }

  .btn-view:hover {
    background: #2563eb;
  }

  .regions-table .col-actions {
    width: 60px;
    text-align: center;
  }

  /* Memory Viewer Modal */
  .memory-viewer-modal {
    background: #1e1e1e;
    border: 1px solid #3a3a3a;
    border-radius: 8px;
    width: 90vw;
    max-width: 1000px;
    max-height: 85vh;
    display: flex;
    flex-direction: column;
    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
  }

  .memory-viewer-modal .modal-header {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 16px;
    border-bottom: 1px solid #3a3a3a;
    background: #252525;
  }

  .memory-viewer-modal .modal-header h3 {
    margin: 0;
    font-size: 14px;
    font-weight: 600;
    color: #e0e0e0;
  }

  .memory-viewer-info {
    display: flex;
    align-items: center;
    gap: 8px;
    flex: 1;
  }

  .memory-viewer-info .mono {
    color: #9ca3af;
    font-size: 12px;
  }

  .region-badge {
    background: #3b82f6;
    color: white;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
  }

  .memory-viewer-toolbar {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 8px 16px;
    border-bottom: 1px solid #3a3a3a;
    background: #1a1a1a;
  }

  .memory-nav {
    display: flex;
    gap: 4px;
  }

  .memory-offset {
    font-size: 12px;
    color: #9ca3af;
  }

  .memory-viewer-content {
    flex: 1;
    overflow: auto;
    padding: 0;
    background: #1e1e1e;
  }

  /* Hex View */
  .hex-view {
    font-size: 12px;
  }

  .hex-header {
    display: flex;
    padding: 6px 12px;
    background: #252525;
    border-bottom: 1px solid #3a3a3a;
    font-weight: 600;
    color: #6b7280;
    font-size: 10px;
    position: sticky;
    top: 0;
    z-index: 1;
  }

  .hex-addr-header {
    width: 160px;
    flex-shrink: 0;
  }

  .hex-bytes-header {
    display: flex;
    gap: 4px;
    flex: 1;
  }

  .hex-col-num {
    width: 20px;
    text-align: center;
  }

  .hex-col-num:nth-child(9) {
    margin-left: 8px;
  }

  .hex-ascii-header {
    width: 140px;
    flex-shrink: 0;
    text-align: center;
  }

  .hex-rows {
    display: flex;
    flex-direction: column;
  }

  .hex-row {
    display: flex;
    padding: 3px 12px;
    border-bottom: 1px solid #2a2a2a;
  }

  .hex-row:hover {
    background: #2a2a2a;
  }

  .hex-addr {
    width: 160px;
    flex-shrink: 0;
    color: #6b7280;
    font-size: 11px;
  }

  .hex-bytes {
    display: flex;
    gap: 4px;
    flex: 1;
  }

  .hex-byte {
    width: 20px;
    text-align: center;
    color: #e0e0e0;
  }

  .hex-byte.zero {
    color: #4b5563;
  }

  .hex-byte.high {
    color: #f59e0b;
  }

  .hex-byte.empty {
    opacity: 0;
  }

  .hex-separator {
    width: 8px;
  }

  .hex-ascii {
    width: 140px;
    flex-shrink: 0;
    letter-spacing: 1px;
    background: #252525;
    padding: 2px 8px;
    border-radius: 3px;
  }

  .ascii-char {
    color: #4b5563;
  }

  .ascii-char.printable {
    color: #10b981;
  }
</style>
