#!/usr/bin/env node

/**
 * freeseek - Local DeepSeek OpenAI-Compatible Proxy
 * High-performance local server with DSML tool calling.
 */

const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const os = require("node:os");
const { exec } = require("node:child_process");

// -----------------------------------------------------------------------------
// Local Configuration & Persistent Token Storage (~/.freeseek/config.json)
// -----------------------------------------------------------------------------
function getConfigFilePath() {
  return path.join(os.homedir(), ".freeseek", "config.json");
}

function getStoredToken() {
  try {
    const configPath = getConfigFilePath();
    if (fs.existsSync(configPath)) {
      const data = JSON.parse(fs.readFileSync(configPath, "utf-8"));
      if (data && typeof data.token === "string") {
        return data.token.trim();
      }
    }
  } catch (e) {}
  return "";
}

function saveStoredToken(token) {
  try {
    let clean = (token || "").trim();
    while (clean.toLowerCase().startsWith("bearer ")) {
      clean = clean.substring(7).trim();
    }
    if (!clean || clean.length < 10) return false;
    const dir = path.join(os.homedir(), ".freeseek");
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const configPath = getConfigFilePath();
    let existing = {};
    if (fs.existsSync(configPath)) {
      try { existing = JSON.parse(fs.readFileSync(configPath, "utf-8")); } catch(e) {}
    }
    existing.token = clean;
    existing.updatedAt = new Date().toISOString();
    fs.writeFileSync(configPath, JSON.stringify(existing, null, 2), "utf-8");
    return true;
  } catch (e) {
    console.error("Failed to save token:", e);
    return false;
  }
}

function clearStoredToken() {
  try {
    const configPath = getConfigFilePath();
    if (fs.existsSync(configPath)) {
      let existing = {};
      try { existing = JSON.parse(fs.readFileSync(configPath, "utf-8")); } catch(e) {}
      delete existing.token;
      fs.writeFileSync(configPath, JSON.stringify(existing, null, 2), "utf-8");
    }
    return true;
  } catch (e) {
    return false;
  }
}

function openBrowser(url) {
  if (process.env.NO_BROWSER || process.argv.includes("--no-browser")) return;
  const platform = process.platform;
  let cmd;
  if (platform === "win32") {
    cmd = `start "" "${url}"`;
  } else if (platform === "darwin") {
    cmd = `open "${url}"`;
  } else {
    cmd = `xdg-open "${url}"`;
  }
  exec(cmd, () => {});
}

async function testDeepSeekToken(token) {
  const clean = (token || "").trim();
  const startTime = Date.now();
  const resp = await fetch("https://chat.deepseek.com/api/v0/chat_session/create", {
    method: "POST",
    headers: {
      "authorization": `Bearer ${clean}`,
      "content-type": "application/json",
      "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
      "origin": "https://chat.deepseek.com",
      "referer": "https://chat.deepseek.com/",
    },
    body: JSON.stringify({ agent: "chat" }),
  });
  const latency = Date.now() - startTime;
  if (!resp.ok) {
    throw new Error(`DeepSeek returned HTTP ${resp.status}: ${resp.statusText}`);
  }
  const data = await resp.json();
  if (data.code !== 0 && data.code !== undefined && data.msg) {
    throw new Error(data.msg);
  }
  return { success: true, latency };
}

// -----------------------------------------------------------------------------
// WebAssembly PoW Solver
// -----------------------------------------------------------------------------
let cachedWasmInstance = null;
function getWasmExports() {
  if (!cachedWasmInstance) {
    let wasmPath = path.join(__dirname, "sha3_wasm_v1.wasm");
    if (!fs.existsSync(wasmPath)) {
      wasmPath = path.join(__dirname, "..", "src", "sha3_wasm_v1.wasm");
    }
    const wasmBytes = fs.readFileSync(wasmPath);
    const wasmModule = new WebAssembly.Module(wasmBytes);
    cachedWasmInstance = new WebAssembly.Instance(wasmModule, {});
  }
  return cachedWasmInstance.exports;
}

function solveDeepSeekPoW(challengeObj) {
  const { memory, wasm_solve, __wbindgen_add_to_stack_pointer, __wbindgen_export_0: alloc } = getWasmExports();
  const { challenge, salt, difficulty, expire_at } = challengeObj;
  const prefix = `${salt}_${expire_at}_`;

  const encoder = new TextEncoder();
  const challengeBytes = encoder.encode(challenge);
  const prefixBytes = encoder.encode(prefix);

  const challengePtr = alloc(challengeBytes.length, 1);
  new Uint8Array(memory.buffer, challengePtr, challengeBytes.length).set(challengeBytes);

  const prefixPtr = alloc(prefixBytes.length, 1);
  new Uint8Array(memory.buffer, prefixPtr, prefixBytes.length).set(prefixBytes);

  const stackRetPtr = __wbindgen_add_to_stack_pointer(-16);

  try {
    wasm_solve(stackRetPtr, challengePtr, challengeBytes.length, prefixPtr, prefixBytes.length, Number(difficulty));
    const dataView = new DataView(memory.buffer);
    const status = dataView.getInt32(stackRetPtr, true);
    if (status === 0) {
      throw new Error("WASM failed to solve PoW challenge");
    }
    const answer = dataView.getFloat64(stackRetPtr + 8, true);
    return Math.floor(answer);
  } finally {
    __wbindgen_add_to_stack_pointer(16);
  }
}

// -----------------------------------------------------------------------------
// DSML Tool Calling Parser
// -----------------------------------------------------------------------------
function normalizeDSML(text) {
  if (!text) return "";
  let s = text.replace(/｜/g, "|");
  s = s.replace(/<\s*(\/?)\s*\|*[\s|]*DSML[\s|]*\|*\s*/gi, "<$1||DSML|| ");
  return s;
}

function parseDSML(text) {
  if (!text) return null;
  const norm = normalizeDSML(text);

  const firstInvokeMatch = norm.match(/<\|+DSML\|+\s*invoke\b[^>]*?\bname=["']?([^"'\s>]+)["']?[^>]*>/i);
  if (!firstInvokeMatch) {
    return null;
  }

  const firstTagMatch = norm.match(/<\|+DSML\|+\s*(?:calls|tool_calls|invoke)[^>]*>/i);
  const contentBefore = firstTagMatch ? norm.substring(0, firstTagMatch.index).trim() : "";

  const toolCalls = [];
  const invokeRegex = /<\|+DSML\|+\s*invoke\b[^>]*?\bname=["']?([^"'\s>]+)["']?[^>]*>([\s\S]*?)(?:<\/\|+DSML\|+\s*invoke[^>]*>|(?=<\|+DSML\|+\s*invoke)|<\/\|+DSML\|+\s*(?:calls|tool_calls)[^>]*>|$)/gi;
  let invMatch;
  let idx = 0;

  while ((invMatch = invokeRegex.exec(norm)) !== null) {
    const name = invMatch[1];
    const paramsBlock = invMatch[2];

    const params = {};
    const paramRegex = /<\|+DSML\|+\s*parameter\b[^>]*?\bname=["']?([^"'\s>]+)["']?[^>]*>([\s\S]*?)(?:<\/\|+DSML\|+\s*parameter[^>]*>|(?=<\|+DSML\|+\s*parameter)|<\/\|+DSML\|+\s*invoke[^>]*>|$)/gi;
    let pMatch;
    while ((pMatch = paramRegex.exec(paramsBlock)) !== null) {
      const pName = pMatch[1];
      const pVal = pMatch[2].trim();
      try {
        params[pName] = JSON.parse(pVal);
      } catch {
        params[pName] = pVal;
      }
    }

    toolCalls.push({
      index: idx++,
      id: "call_" + crypto.randomUUID().replace(/-/g, "").substring(0, 10),
      type: "function",
      function: {
        name: name,
        arguments: JSON.stringify(params),
      },
    });
  }

  if (toolCalls.length === 0) return null;
  return { contentBefore, toolCalls };
}

// -----------------------------------------------------------------------------
// Image Processing
// -----------------------------------------------------------------------------
function parseDataUri(dataUri) {
  const match = dataUri.match(/^data:([^;]+);base64,(.+)$/);
  if (!match) return null;
  const mimeType = match[1];
  const b64Data = match[2];
  const buf = Buffer.from(b64Data, "base64");
  let ext = "png";
  if (mimeType.includes("jpeg") || mimeType.includes("jpg")) ext = "jpg";
  else if (mimeType.includes("webp")) ext = "webp";
  else if (mimeType.includes("gif")) ext = "gif";
  return { bytes: new Uint8Array(buf), mimeType, filename: `image.${ext}` };
}

async function getImageInfo(url) {
  if (!url || typeof url !== "string") return null;
  if (url.startsWith("data:")) {
    return parseDataUri(url);
  } else if (url.startsWith("http://") || url.startsWith("https://")) {
    try {
      const resp = await fetch(url);
      if (!resp.ok) return null;
      const arrayBuffer = await resp.arrayBuffer();
      const mimeType = resp.headers.get("content-type") || "image/png";
      let ext = "png";
      if (mimeType.includes("jpeg") || mimeType.includes("jpg")) ext = "jpg";
      else if (mimeType.includes("webp")) ext = "webp";
      else if (mimeType.includes("gif")) ext = "gif";
      return {
        bytes: new Uint8Array(arrayBuffer),
        mimeType: mimeType,
        filename: `image.${ext}`,
      };
    } catch {
      return null;
    }
  }
  return null;
}

function extractImagesFromMessages(messages) {
  const urls = [];
  if (!Array.isArray(messages)) return urls;
  for (const m of messages) {
    if (Array.isArray(m.content)) {
      for (const part of m.content) {
        if (part && part.type === "image_url" && part.image_url && part.image_url.url) {
          urls.push(part.image_url.url);
        }
      }
    }
  }
  return urls;
}

async function uploadImageToDeepSeek(imgInfo, token, sessionId, baseHeaders) {
  try {
    const uploadHeaders = {
      ...baseHeaders,
      "referer": `https://chat.deepseek.com/a/chat/s/${sessionId}`,
    };
    delete uploadHeaders["content-type"];

    const formData = new FormData();
    const blob = new Blob([imgInfo.bytes], { type: imgInfo.mimeType });
    formData.append("file", blob, imgInfo.filename);

    const uploadResp = await fetch("https://chat.deepseek.com/api/v0/file/upload_file", {
      method: "POST",
      headers: uploadHeaders,
      body: formData,
    });

    if (!uploadResp.ok) return null;
    const uploadData = await uploadResp.json();
    if (uploadData.code !== 0 || !uploadData.data || !uploadData.data.biz_data) return null;

    const fileId = uploadData.data.biz_data.id || uploadData.data.biz_data.file_id;
    if (!fileId) return null;

    // Brief poll to wait for status to be ready
    for (let poll = 0; poll < 4; poll++) {
      try {
        const statusResp = await fetch(
          `https://chat.deepseek.com/api/v0/file/fetch_files?file_ids=${encodeURIComponent(fileId)}`,
          { method: "GET", headers: uploadHeaders }
        );
        if (statusResp.ok) {
          const statusData = await statusResp.json();
          const files = statusData.data?.biz_data?.files || [];
          const f = files.find((item) => item.id === fileId);
          if (f && f.status && !["PENDING", "UPLOADING", "PROCESSING"].includes(f.status.toUpperCase())) {
            break;
          }
        }
      } catch {}
      await new Promise((r) => setTimeout(r, 300));
    }

    return fileId;
  } catch (err) {
    console.error("Image upload error:", err);
    return null;
  }
}

// -----------------------------------------------------------------------------
// Prompt Formatting & Session Management
// -----------------------------------------------------------------------------
function extractMessageContent(content) {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    const textParts = [];
    for (const part of content) {
      if (part && part.type === "text" && part.text) {
        textParts.push(part.text);
      }
    }
    return textParts.join("\n");
  }
  return String(content || "");
}

function formatPromptWithTools(messages, tools) {
  let promptParts = [];

  if (tools && tools.length > 0) {
    const toolsDesc = JSON.stringify(tools, null, 2);
    promptParts.push(
      `[SYSTEM INSTRUCTION: TOOLS AVAILABLE]\nYou have access to the following tools:\n${toolsDesc}\n\n` +
      `When you need to execute a tool, write your response in this exact format:\n` +
      `<||DSML|| calls>\n` +
      `<||DSML|| invoke name="tool_name">\n` +
      `<||DSML|| parameter name="arg_name" string="true">value</||DSML|| parameter>\n` +
      `</||DSML|| invoke>\n` +
      `</||DSML|| calls>\n`
    );
  }

  const totalLength = messages.reduce((acc, m) => acc + (typeof m.content === "string" ? m.content.length : 1000), 0);
  const isLargeChat = totalLength > 60000;
  const recentThresholdIndex = Math.max(0, messages.length - 12);

  for (let i = 0; i < messages.length; i++) {
    const m = messages[i];
    const role = (m.role || "user").toUpperCase();
    let contentText = extractMessageContent(m.content);

    if (isLargeChat && i < recentThresholdIndex) {
      if (role === "TOOL" || role === "FUNCTION") {
        if (contentText.length > 1200) {
          contentText = contentText.substring(0, 1200) + "\n...[truncated historical tool output]...";
        }
      } else if (contentText.length > 3000) {
        contentText = contentText.substring(0, 3000) + "\n...[compacted earlier message]...";
      }
    }

    if (m.tool_calls && Array.isArray(m.tool_calls) && m.tool_calls.length > 0) {
      let dsmlCalls = "<||DSML|| calls>\n";
      for (const tc of m.tool_calls) {
        const fnName = tc.function?.name || "tool";
        let fnArgs = {};
        try {
          fnArgs = typeof tc.function?.arguments === "string" ? JSON.parse(tc.function.arguments) : tc.function?.arguments || {};
        } catch {
          fnArgs = { raw: tc.function?.arguments };
        }
        dsmlCalls += `<||DSML|| invoke name="${fnName}">\n`;
        for (const [k, v] of Object.entries(fnArgs)) {
          const valStr = typeof v === "object" ? JSON.stringify(v) : String(v);
          dsmlCalls += `<||DSML|| parameter name="${k}" string="true">${valStr}</||DSML|| parameter>\n`;
        }
        dsmlCalls += `</||DSML|| invoke>\n`;
      }
      dsmlCalls += `</||DSML|| calls>`;
      promptParts.push(`[${role}]: ${contentText ? contentText + "\n" : ""}${dsmlCalls}`);
    } else if (role === "TOOL" || role === "FUNCTION") {
      promptParts.push(`[TOOL RESULT]:\n${contentText}`);
    } else {
      promptParts.push(`[${role}]: ${contentText}`);
    }
  }

  return promptParts.join("\n\n");
}

const activeSessionCache = new Map();
const SESSION_TTL_MS = 15 * 60 * 1000;

async function getOrCreateSession(token, baseHeaders) {
  const cached = activeSessionCache.get(token);
  const now = Date.now();
  if (cached && (now - cached.created) < SESSION_TTL_MS) {
    return cached.sessionId;
  }

  let sessionId = null;
  let lastSessError = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const sessResp = await fetch("https://chat.deepseek.com/api/v0/chat_session/create", {
        method: "POST",
        headers: baseHeaders,
        body: JSON.stringify({}),
      });
      if (!sessResp.ok) {
        const text = await sessResp.text();
        throw new Error(`DeepSeek session creation HTTP ${sessResp.status}: ${text.substring(0, 100)}`);
      }
      const sessData = await sessResp.json();
      if (sessData.code !== 0) {
        throw new Error(`Failed to create DeepSeek session: ${sessData.msg || "Unknown error"}`);
      }
      sessionId = sessData.data.biz_data.chat_session.id;
      activeSessionCache.set(token, { sessionId, created: Date.now() });
      return sessionId;
    } catch (err) {
      lastSessError = err;
      if (attempt < 2) await new Promise((r) => setTimeout(r, 300 * (attempt + 1)));
    }
  }

  if (cached && cached.sessionId) return cached.sessionId;
  throw lastSessError || new Error("Failed to create DeepSeek session after retries");
}

async function dispatchDeepSeekCompletion(prompt, messages, tools, baseHeaders, token, thinkingEnabled, imageUrls, options = {}) {
  let lastErr = null;
  const targetSessionId = options.sessionId || null;
  const parentMessageId = options.parentMessageId !== undefined ? options.parentMessageId : null;
  const useThinking = options.thinkingEnabled !== undefined ? options.thinkingEnabled : thinkingEnabled;

  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const sessionId = targetSessionId || await getOrCreateSession(token, baseHeaders);

      const refFileIds = [];
      if (imageUrls.length > 0) {
        for (const imgUrl of imageUrls) {
          try {
            const imgInfo = await getImageInfo(imgUrl);
            if (imgInfo) {
              const fileId = await uploadImageToDeepSeek(imgInfo, token, sessionId, baseHeaders);
              if (fileId) refFileIds.push(fileId);
            }
          } catch {}
        }
      }
      const uniqueFileIds = [...new Set(refFileIds)];

      let powHeaderValue = null;
      for (let powAttempt = 0; powAttempt < 5; powAttempt++) {
        try {
          const powResp = await fetch("https://chat.deepseek.com/api/v0/chat/create_pow_challenge", {
            method: "POST",
            headers: baseHeaders,
            body: JSON.stringify({ target_path: "/api/v0/chat/completion" }),
          });
          if (!powResp.ok) throw new Error(`PoW endpoint HTTP ${powResp.status}`);
          const powData = await powResp.json();
          if (powData.code !== 0) throw new Error(powData.msg || "PoW challenge error");
          const challengeObj = powData.data.biz_data.challenge;

          // Local node runs fast without worker CPU limits
          const answer = solveDeepSeekPoW(challengeObj);

          powHeaderValue = btoa(JSON.stringify({
            algorithm: challengeObj.algorithm,
            challenge: challengeObj.challenge,
            salt: challengeObj.salt,
            answer: answer,
            signature: challengeObj.signature,
            target_path: challengeObj.target_path,
          }));
          break;
        } catch (pe) {
          if (powAttempt < 4) await new Promise((r) => setTimeout(r, 200 * (powAttempt + 1)));
        }
      }

      if (!powHeaderValue) {
        throw new Error("DeepSeek PoW challenge failed (503)");
      }

      const completionHeaders = {
        ...baseHeaders,
        "referer": `https://chat.deepseek.com/a/chat/s/${sessionId}`,
        "x-ds-pow-response": powHeaderValue,
      };

      const completionPayload = {
        chat_session_id: sessionId,
        parent_message_id: parentMessageId,
        prompt: prompt,
        ref_file_ids: uniqueFileIds,
        thinking_enabled: useThinking,
        search_enabled: false,
      };

      const dsResponse = await fetch("https://chat.deepseek.com/api/v0/chat/completion", {
        method: "POST",
        headers: completionHeaders,
        body: JSON.stringify(completionPayload),
      });

      if (dsResponse.ok) {
        return { response: dsResponse, sessionId };
      }

      activeSessionCache.delete(token);

      if ([429, 500, 502, 503, 504].includes(dsResponse.status) && attempt < 2) {
        await new Promise((r) => setTimeout(r, 800));
        continue;
      }

      const errorText = await dsResponse.text();
      throw new Error(`DeepSeek completion HTTP ${dsResponse.status}: ${errorText.substring(0, 100)}`);
    } catch (e) {
      lastErr = e;
      activeSessionCache.delete(token);
      if (attempt < 2) await new Promise((r) => setTimeout(r, 800));
    }
  }

  throw lastErr || new Error("Failed to connect to DeepSeek (503)");
}

function writeSSE(res, data) {
  res.write(`data: ${JSON.stringify(data)}\n\n`);
}

function emitStreamDelta(res, completionId, model, created, fragmentType, text) {
  const delta = {};
  if (fragmentType === "THINK") {
    delta.reasoning_content = text;
  } else {
    delta.content = text;
  }
  writeSSE(res, {
    id: completionId,
    object: "chat.completion.chunk",
    created: created,
    model: model,
    choices: [{ index: 0, delta: delta, finish_reason: null }],
  });
}


// -----------------------------------------------------------------------------
// HTTP Request Router & Handler
// -----------------------------------------------------------------------------
const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "*",
};

async function handleChatCompletion(body, token, res) {
  const messages = body.messages || [];
  const tools = body.tools || [];
  const isStream = body.stream === true;
  const model = body.model || "deepseek-reasoner";
  const isFastMode = model.toLowerCase().includes("chat") || model.toLowerCase().includes("flash");
  const thinkingEnabled = !isFastMode;

  const prompt = formatPromptWithTools(messages, tools);

  const baseHeaders = {
    "accept": "*/*",
    "accept-language": "en-US,en;q=0.9",
    "authorization": token,
    "content-type": "application/json",
    "origin": "https://chat.deepseek.com",
    "referer": "https://chat.deepseek.com/",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36",
    "x-client-platform": "web",
    "x-client-version": "2.5.0",
  };

  const imageUrls = extractImagesFromMessages(messages);
  const completionId = "chatcmpl-" + crypto.randomUUID().replace(/-/g, "").substring(0, 16);
  const createdTimestamp = Math.floor(Date.now() / 1000);

  if (isStream) {
    res.writeHead(200, {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
      ...CORS_HEADERS,
    });

    writeSSE(res, {
      id: completionId,
      object: "chat.completion.chunk",
      created: createdTimestamp,
      model: model,
      choices: [{ index: 0, delta: { role: "assistant" }, finish_reason: null }],
    });

    let dsResponse = null;
    let activeSessionId = null;
    try {
      const dispatchResult = await dispatchDeepSeekCompletion(prompt, messages, tools, baseHeaders, token, thinkingEnabled, imageUrls);
      dsResponse = dispatchResult.response;
      activeSessionId = dispatchResult.sessionId;
    } catch (dispatchErr) {
      console.error("  [Error] DeepSeek dispatch error:", dispatchErr.message);
      const failMsg = "DeepSeek's servers are currently experiencing high traffic. Please click 'continue' or send your message again in a moment.";
      emitStreamDelta(res, completionId, model, createdTimestamp, "RESPONSE", failMsg);
      writeSSE(res, {
        id: completionId,
        object: "chat.completion.chunk",
        created: createdTimestamp,
        model: model,
        choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
      });
      res.write("data: [DONE]\n\n");
      res.end();
      return;
    }

    let lastResponseMsgId = null;
    const reader = dsResponse.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let currentFragmentType = thinkingEnabled ? "THINK" : "RESPONSE";
    let accumulatedResponseText = "";
    let accumulatedThinkText = "";
    let pendingResponseBuffer = "";
    let inToolCallBlock = false;
    let hasEmittedContent = false;

    async function handleResponseChunk(text) {
      if (!text) return;
      accumulatedResponseText += text;
      if (inToolCallBlock) return;

      pendingResponseBuffer += text;

      const tagMatch = pendingResponseBuffer.search(/<\s*(\/?)\s*(?:[|｜]|DSML)/i);
      if (tagMatch !== -1) {
        inToolCallBlock = true;
        const beforeTag = pendingResponseBuffer.substring(0, tagMatch);
        if (beforeTag) {
          emitStreamDelta(res, completionId, model, createdTimestamp, "RESPONSE", beforeTag);
          hasEmittedContent = true;
        }
        pendingResponseBuffer = "";
        return;
      }

      const partialTagMatch = pendingResponseBuffer.match(/<\s*(\/?)\s*(?:[|｜]|D|DS|DSM)?$/i);
      if (partialTagMatch) {
        const cutIdx = partialTagMatch.index;
        if (cutIdx > 0) {
          const safePrefix = pendingResponseBuffer.substring(0, cutIdx);
          emitStreamDelta(res, completionId, model, createdTimestamp, "RESPONSE", safePrefix);
          hasEmittedContent = true;
          pendingResponseBuffer = pendingResponseBuffer.substring(cutIdx);
        }
        return;
      }

      emitStreamDelta(res, completionId, model, createdTimestamp, "RESPONSE", pendingResponseBuffer);
      hasEmittedContent = true;
      pendingResponseBuffer = "";
    }

    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop();

        for (const line of lines) {
          if (line.startsWith("event: close") || line.includes("[DONE]")) break;
          if (line.startsWith("data:")) {
            const dataStr = line.substring(5).trim();
            if (!dataStr) continue;

            try {
              const data = JSON.parse(dataStr);
              if (data.response_message_id) {
                lastResponseMsgId = data.response_message_id;
              }
              if (data.v && data.v.response && (data.v.response.message_id || data.v.response.id)) {
                lastResponseMsgId = data.v.response.message_id || data.v.response.id || lastResponseMsgId;
              }

              if (data.v && data.v.response && data.v.response.fragments && data.v.response.fragments.length > 0) {
                currentFragmentType = data.v.response.fragments[0].type || "THINK";
                const initialContent = data.v.response.fragments[0].content || "";
                if (initialContent) {
                  if (currentFragmentType === "THINK") {
                    accumulatedThinkText += initialContent;
                    emitStreamDelta(res, completionId, model, createdTimestamp, "THINK", initialContent);
                  } else {
                    await handleResponseChunk(initialContent);
                  }
                }
              }

              if (data.p === "response/fragments" && data.o === "APPEND" && Array.isArray(data.v) && data.v.length > 0) {
                currentFragmentType = data.v[0].type || "RESPONSE";
                const c = data.v[0].content || "";
                if (c) {
                  if (currentFragmentType === "THINK") {
                    accumulatedThinkText += c;
                    emitStreamDelta(res, completionId, model, createdTimestamp, "THINK", c);
                  } else {
                    await handleResponseChunk(c);
                  }
                }
              }

              if (data.v && typeof data.v === "string" && (!data.p || !data.p.includes("status"))) {
                if (currentFragmentType === "THINK") {
                  accumulatedThinkText += data.v;
                  emitStreamDelta(res, completionId, model, createdTimestamp, "THINK", data.v);
                } else {
                  await handleResponseChunk(data.v);
                }
              }
            } catch {}
          }
        }
      }

      if (!inToolCallBlock && pendingResponseBuffer) {
        emitStreamDelta(res, completionId, model, createdTimestamp, "RESPONSE", pendingResponseBuffer);
        hasEmittedContent = true;
        pendingResponseBuffer = "";
      }

      const dsml = parseDSML(accumulatedResponseText);
      if (dsml && dsml.toolCalls.length > 0) {
        if (!hasEmittedContent && dsml.contentBefore) {
          emitStreamDelta(res, completionId, model, createdTimestamp, "RESPONSE", dsml.contentBefore);
          hasEmittedContent = true;
        }
        writeSSE(res, {
          id: completionId,
          object: "chat.completion.chunk",
          created: createdTimestamp,
          model: model,
          choices: [{ index: 0, delta: { tool_calls: dsml.toolCalls }, finish_reason: null }],
        });
        writeSSE(res, {
          id: completionId,
          object: "chat.completion.chunk",
          created: createdTimestamp,
          model: model,
          choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }],
        });
        res.write("data: [DONE]\n\n");
        return;
      } else {
        if (inToolCallBlock) {
          const cleanText = accumulatedResponseText.replace(/<\s*(\/?)\s*\|*[\s|]*DSML[\s|]*\|*[^>]*>/gi, "").trim();
          if (!hasEmittedContent && cleanText) {
            emitStreamDelta(res, completionId, model, createdTimestamp, "RESPONSE", cleanText);
            hasEmittedContent = true;
          }
        }


        if (!hasEmittedContent) {
          const fallback = accumulatedResponseText.trim() || accumulatedThinkText.trim() || " ";
          emitStreamDelta(res, completionId, model, createdTimestamp, "RESPONSE", fallback);
          hasEmittedContent = true;
        }

        writeSSE(res, {
          id: completionId,
          object: "chat.completion.chunk",
          created: createdTimestamp,
          model: model,
          choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
        });
      }

      res.write("data: [DONE]\n\n");
    } catch (streamErr) {
      console.error("  [Stream Error]", streamErr);
      if (!hasEmittedContent) {
        const fallback = accumulatedResponseText.trim() || accumulatedThinkText.trim() || "DeepSeek's servers are currently experiencing high traffic. Please click 'continue' or send your message again in a moment.";
        emitStreamDelta(res, completionId, model, createdTimestamp, "RESPONSE", fallback);
      }
      writeSSE(res, {
        id: completionId,
        object: "chat.completion.chunk",
        created: createdTimestamp,
        model: model,
        choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
      });
      res.write("data: [DONE]\n\n");
    } finally {
      res.end();
    }
  } else {
    // Non-streaming Response
    try {
      const dispatchResult = await dispatchDeepSeekCompletion(prompt, messages, tools, baseHeaders, token, thinkingEnabled, imageUrls);
      const dsResponse = dispatchResult.response;
      const activeSessionId = dispatchResult.sessionId;
      let lastResponseMsgId = null;
      const reader = dsResponse.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let thinkAccumulated = "";
      let responseAccumulated = "";
      let currentFragmentType = thinkingEnabled ? "THINK" : "RESPONSE";

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop();

        for (const line of lines) {
          if (line.startsWith("data:")) {
            const dataStr = line.substring(5).trim();
            if (!dataStr) continue;
            try {
              const data = JSON.parse(dataStr);
              if (data.response_message_id) {
                lastResponseMsgId = data.response_message_id;
              }
              if (data.v && data.v.response && (data.v.response.message_id || data.v.response.id)) {
                lastResponseMsgId = data.v.response.message_id || data.v.response.id || lastResponseMsgId;
              }

              if (data.v && data.v.response && data.v.response.fragments && data.v.response.fragments.length > 0) {
                currentFragmentType = data.v.response.fragments[0].type || "THINK";
                const c = data.v.response.fragments[0].content || "";
                if (currentFragmentType === "THINK") thinkAccumulated += c;
                else responseAccumulated += c;
              }
              if (data.p === "response/fragments" && data.o === "APPEND" && Array.isArray(data.v) && data.v.length > 0) {
                currentFragmentType = data.v[0].type || "RESPONSE";
                const c = data.v[0].content || "";
                if (currentFragmentType === "THINK") thinkAccumulated += c;
                else responseAccumulated += c;
              }
              if (data.v && typeof data.v === "string" && (!data.p || !data.p.includes("status"))) {
                if (currentFragmentType === "THINK") thinkAccumulated += data.v;
                else responseAccumulated += data.v;
              }
            } catch {}
          }
        }
      }

      const dsml = parseDSML(responseAccumulated);
      let messageContent = responseAccumulated;
      let toolCalls = undefined;
      let finishReason = "stop";

      if (dsml && dsml.toolCalls.length > 0) {
        messageContent = dsml.contentBefore || null;
        toolCalls = dsml.toolCalls;
        finishReason = "tool_calls";
      } else {
        messageContent = responseAccumulated;
      }

      res.writeHead(200, { "Content-Type": "application/json", ...CORS_HEADERS });
      res.end(JSON.stringify({
        id: completionId,
        object: "chat.completion",
        created: createdTimestamp,
        model: model,
        choices: [{
          index: 0,
          message: {
            role: "assistant",
            content: messageContent,
            reasoning_content: thinkAccumulated || undefined,
            tool_calls: toolCalls,
          },
          finish_reason: finishReason,
        }],
      }));
    } catch (err) {
      res.writeHead(200, { "Content-Type": "application/json", ...CORS_HEADERS });
      res.end(JSON.stringify({
        id: completionId,
        object: "chat.completion",
        created: createdTimestamp,
        model: model,
        choices: [{
          index: 0,
          message: {
            role: "assistant",
            content: "DeepSeek's servers are currently experiencing high traffic. Please click 'continue' or send your message again in a moment.",
          },
          finish_reason: "stop",
        }],
      }));
    }
  }
}

// -----------------------------------------------------------------------------
// Server Initialization
// -----------------------------------------------------------------------------
function startServer(port = 8787) {
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || "127.0.0.1:" + port}`);

    if (req.method === "OPTIONS") {
      res.writeHead(204, CORS_HEADERS);
      res.end();
      return;
    }

    // Health & Status endpoint
    if (url.pathname === "/health" || url.pathname === "/api/status") {
      const storedToken = getStoredToken();
      const activeToken = storedToken || process.env.DEEPSEEK_AUTH_TOKEN || "";
      const hasToken = !!activeToken && activeToken.length >= 10;
      const masked = hasToken
        ? `${activeToken.substring(0, 6)}...${activeToken.substring(activeToken.length - 4)}`
        : "";
      res.writeHead(200, { "Content-Type": "application/json", ...CORS_HEADERS });
      res.end(JSON.stringify({
        status: "ok",
        mode: "local-node",
        hasToken,
        tokenPreview: masked,
        port,
        configPath: getConfigFilePath(),
        timestamp: new Date().toISOString(),
      }));
      return;
    }

    // Token Management API: Save Token
    if (url.pathname === "/api/save-token" && req.method === "POST") {
      let bodyStr = "";
      req.on("data", (chunk) => { bodyStr += chunk; });
      req.on("end", () => {
        try {
          const data = JSON.parse(bodyStr);
          const token = data.token;
          if (!token || typeof token !== "string" || token.trim().length < 10) {
            res.writeHead(400, { "Content-Type": "application/json", ...CORS_HEADERS });
            res.end(JSON.stringify({ success: false, error: "Invalid token: must be at least 10 characters." }));
            return;
          }
          const saved = saveStoredToken(token);
          if (saved) {
            console.log(`[${new Date().toLocaleTimeString()}] DeepSeek token saved to ${getConfigFilePath()}`);
            res.writeHead(200, { "Content-Type": "application/json", ...CORS_HEADERS });
            res.end(JSON.stringify({ success: true, message: "Token saved successfully!" }));
          } else {
            res.writeHead(500, { "Content-Type": "application/json", ...CORS_HEADERS });
            res.end(JSON.stringify({ success: false, error: "Failed to write configuration file." }));
          }
        } catch (e) {
          res.writeHead(400, { "Content-Type": "application/json", ...CORS_HEADERS });
          res.end(JSON.stringify({ success: false, error: "Invalid JSON: " + e.message }));
        }
      });
      return;
    }

    // Token Management API: Clear Token
    if (url.pathname === "/api/clear-token" && req.method === "POST") {
      clearStoredToken();
      console.log(`[${new Date().toLocaleTimeString()}] DeepSeek token disconnected`);
      res.writeHead(200, { "Content-Type": "application/json", ...CORS_HEADERS });
      res.end(JSON.stringify({ success: true, message: "Token disconnected." }));
      return;
    }

    // Token Management API: Test Token
    if (url.pathname === "/api/test-token" && req.method === "POST") {
      let bodyStr = "";
      req.on("data", (chunk) => { bodyStr += chunk; });
      req.on("end", async () => {
        let testTok = "";
        try {
          if (bodyStr.trim()) {
            const data = JSON.parse(bodyStr);
            if (data.token) testTok = data.token;
          }
        } catch (e) {}
        if (!testTok) {
          testTok = getStoredToken() || process.env.DEEPSEEK_AUTH_TOKEN || "";
        }
        if (!testTok || testTok.length < 10) {
          res.writeHead(400, { "Content-Type": "application/json", ...CORS_HEADERS });
          res.end(JSON.stringify({ success: false, error: "No token saved or provided to test." }));
          return;
        }
        try {
          const result = await testDeepSeekToken(testTok);
          res.writeHead(200, { "Content-Type": "application/json", ...CORS_HEADERS });
          res.end(JSON.stringify({ success: true, latency: result.latency }));
        } catch (testErr) {
          res.writeHead(200, { "Content-Type": "application/json", ...CORS_HEADERS });
          res.end(JSON.stringify({ success: false, error: testErr.message }));
        }
      });
      return;
    }

    // Models listing
    if (url.pathname === "/v1/models" || url.pathname === "/models") {
      res.writeHead(200, { "Content-Type": "application/json", ...CORS_HEADERS });
      res.end(JSON.stringify({
        object: "list",
        data: [
          { id: "deepseek-reasoner", object: "model", created: 1700000000, owned_by: "deepseek" },
          { id: "deepseek-chat", object: "model", created: 1700000000, owned_by: "deepseek" },
        ],
      }));
      return;
    }

    // OpenAI Chat Completions
    if (url.pathname === "/v1/chat/completions" || url.pathname === "/chat/completions") {
      const authHeader = req.headers["authorization"] || "";
      let callerToken = authHeader.trim();
      while (callerToken.toLowerCase().startsWith("bearer ")) {
        callerToken = callerToken.substring(7).trim();
      }

      // Check if caller sent a dummy key or if we should use stored token
      const isDummy = !callerToken ||
        callerToken.toLowerCase() === "dummy" ||
        callerToken.toLowerCase() === "sk-dummy" ||
        callerToken.toLowerCase() === "none" ||
        callerToken.toLowerCase() === "test" ||
        callerToken.toLowerCase() === "freeseek" ||
        callerToken.length < 20;

      let effectiveToken = "";
      if (!isDummy) {
        effectiveToken = callerToken;
      } else {
        effectiveToken = process.env.DEEPSEEK_AUTH_TOKEN || getStoredToken();
      }

      if (!effectiveToken || effectiveToken.length < 10) {
        res.writeHead(401, { "Content-Type": "application/json", ...CORS_HEADERS });
        res.end(JSON.stringify({
          error: {
            message: `No DeepSeek token found! Please open http://127.0.0.1:${port} to connect your token, or set DEEPSEEK_AUTH_TOKEN.`,
            type: "auth_required",
            dashboard_url: `http://127.0.0.1:${port}`,
          },
        }));
        return;
      }

      let bodyStr = "";
      req.on("data", (chunk) => { bodyStr += chunk; });
      req.on("end", async () => {
        try {
          const body = JSON.parse(bodyStr);
          const modelName = body.model || "deepseek-reasoner";
          console.log(`[${new Date().toLocaleTimeString()}] Chat request -> model: ${modelName}, stream: ${body.stream === true}`);
          await handleChatCompletion(body, `Bearer ${effectiveToken}`, res);
        } catch (err) {
          console.error("Request parse error:", err);
          res.writeHead(200, { "Content-Type": "application/json", ...CORS_HEADERS });
          res.end(JSON.stringify({
            id: "chatcmpl-" + crypto.randomUUID().replace(/-/g, "").substring(0, 16),
            object: "chat.completion",
            created: Math.floor(Date.now() / 1000),
            model: "deepseek-reasoner",
            choices: [{
              index: 0,
              message: {
                role: "assistant",
                content: "DeepSeek's servers are currently experiencing high traffic. Please send your message again in a moment.",
              },
              finish_reason: "stop",
            }],
          }));
        }
      });
      return;
    }

    // Local Setup & Dashboard HTML (Monochrome, Minimalist, Zero Emojis)
    const syncBookmarkletCode = `javascript:(function(){try{let t='';const raw=localStorage.getItem('userToken');if(raw){try{const p=JSON.parse(raw);t=(p&&typeof p==='object')?(p.value||p.token||''):p;}catch(e){t=raw;}}if(typeof t==='string'){t=t.trim();while(t.toLowerCase().startsWith('bearer '))t=t.substring(7).trim();}if(!t||t==='null'||t==='undefined'||t==='{}'||t.length<10){return alert('Token NOT found: Please log in to chat.deepseek.com first and try again.');}try{navigator.clipboard.writeText(t);}catch(e){}try{const ta=document.createElement('textarea');ta.value=t;document.body.appendChild(ta);ta.select();document.execCommand('copy');document.body.removeChild(ta);}catch(e){}fetch('http://127.0.0.1:${port}/api/save-token',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:t}),mode:'cors'}).then(function(res){if(res.ok){alert('Connected to local Freeseek! Your token is synced. You can now use Cursor with API Key: dummy');}else{alert('Token copied to clipboard! (Could not auto-sync to local port ${port})');}}).catch(function(){alert('Token copied to clipboard! Paste it into the Freeseek setup dashboard at http://127.0.0.1:${port}');});}catch(e){alert('Error: '+e);}})();`;

    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", ...CORS_HEADERS });
    res.end(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>freeseek - Local Proxy Dashboard</title>
  <style>
    :root {
      --bg: #ffffff;
      --card-bg: #ffffff;
      --border: #e5e5e5;
      --border-dark: #111111;
      --text: #0a0a0a;
      --text-muted: #666666;
      --text-subtle: #888888;
      --code-bg: #f5f5f5;
      --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      --font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: var(--font-sans);
      line-height: 1.6;
      padding: 40px 20px;
    }
    .container {
      max-width: 680px;
      margin: 0 auto;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--border);
    }
    .logo-title {
      font-size: 20px;
      font-weight: 700;
      letter-spacing: -0.5px;
      text-transform: uppercase;
    }
    .logo-sub {
      font-size: 13px;
      color: var(--text-muted);
    }
    .status-badge {
      display: inline-flex;
      align-items: center;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 600;
      border: 1px solid var(--border);
    }
    .status-badge.connected {
      background: #000000;
      color: #ffffff;
      border-color: #000000;
    }
    .status-badge.disconnected {
      background: #ffffff;
      color: var(--text-muted);
      border-color: var(--border);
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 24px;
      margin-bottom: 20px;
    }
    .card-title {
      font-size: 16px;
      font-weight: 600;
      margin-bottom: 12px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .step-num {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 22px;
      height: 22px;
      background: #000000;
      color: #ffffff;
      border-radius: 50%;
      font-size: 11px;
      font-weight: 700;
    }
    p {
      color: var(--text-muted);
      font-size: 14px;
      margin-bottom: 14px;
    }
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 9px 16px;
      border-radius: 6px;
      font-size: 13px;
      font-weight: 600;
      text-decoration: none;
      cursor: pointer;
      transition: all 0.15s ease;
      border: 1px solid transparent;
      font-family: inherit;
    }
    .btn-primary {
      background: #000000;
      color: #ffffff;
      border-color: #000000;
    }
    .btn-primary:hover {
      background: #262626;
    }
    .btn-outline {
      background: #ffffff;
      color: var(--text);
      border-color: var(--border-dark);
    }
    .btn-outline:hover {
      background: #f5f5f5;
    }
    .btn-danger {
      background: #ffffff;
      color: #000000;
      border-color: var(--border);
      font-size: 12px;
      padding: 4px 8px;
    }
    .btn-danger:hover {
      border-color: #000000;
    }
    .btn-copy {
      padding: 4px 10px;
      font-size: 11px;
      font-weight: 600;
      background: #ffffff;
      border: 1px solid var(--border);
      border-radius: 4px;
      cursor: pointer;
    }
    .btn-copy:hover {
      border-color: #000000;
    }
    .bookmarklet-box {
      border: 2px dashed #000000;
      border-radius: 8px;
      padding: 20px;
      text-align: center;
      background: #fafafa;
      margin: 14px 0;
    }
    .bookmarklet-btn {
      display: inline-block;
      padding: 10px 20px;
      background: #000000;
      color: #ffffff;
      text-decoration: none;
      border-radius: 6px;
      font-weight: 600;
      font-size: 13px;
      cursor: grab;
      box-shadow: 0 2px 6px rgba(0,0,0,0.1);
    }
    .bookmarklet-btn:active {
      cursor: grabbing;
    }
    .input-group {
      display: flex;
      gap: 8px;
      margin-top: 10px;
    }
    .input-field {
      flex: 1;
      padding: 9px 12px;
      border: 1px solid var(--border);
      border-radius: 6px;
      font-family: var(--font-mono);
      font-size: 12px;
      outline: none;
    }
    .input-field:focus {
      border-color: #000000;
    }
    .config-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 10px;
      font-size: 13px;
    }
    .config-table tr {
      border-bottom: 1px solid var(--border);
    }
    .config-table tr:last-child {
      border-bottom: none;
    }
    .config-table td {
      padding: 10px 0;
      vertical-align: middle;
    }
    .config-label {
      font-weight: 600;
      width: 140px;
    }
    .config-val {
      font-family: var(--font-mono);
      background: var(--code-bg);
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 12px;
    }
    .toast {
      position: fixed;
      bottom: 24px;
      right: 24px;
      background: #000000;
      color: #ffffff;
      padding: 10px 18px;
      border-radius: 6px;
      font-size: 13px;
      font-weight: 500;
      display: none;
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
      z-index: 1000;
    }
    kbd {
      background: #eee;
      border: 1px solid #ccc;
      border-radius: 3px;
      padding: 1px 5px;
      font-size: 11px;
      font-family: var(--font-mono);
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <div class="logo-title">freeseek</div>
        <div class="logo-sub">Local DeepSeek to OpenAI Proxy</div>
      </div>
      <div id="status-badge" class="status-badge disconnected">Checking status...</div>
    </header>

    <!-- Overview Card -->
    <div class="card">
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
          <div style="font-size: 13px; color: var(--text-muted);">Current Local Connection</div>
          <div style="font-size: 15px; font-weight: 600; margin-top: 2px;" id="token-status-text">Checking stored credentials...</div>
        </div>
        <div>
          <button id="clear-btn" class="btn btn-danger" style="display: none;" onclick="disconnectToken()">Disconnect</button>
        </div>
      </div>
    </div>

    <!-- Step 1: Open DeepSeek -->
    <div class="card">
      <div class="card-title">
        <span class="step-num">1</span>
        <span>Open DeepSeek & Sign In</span>
      </div>
      <p>Log in to your account at chat.deepseek.com. If you do not have an account yet, create one for free in 10 seconds.</p>
      <a href="https://chat.deepseek.com" target="_blank" rel="noopener noreferrer" class="btn btn-outline">
        Open chat.deepseek.com &rarr;
      </a>
    </div>

    <!-- Step 2: Sync Account -->
    <div class="card">
      <div class="card-title">
        <span class="step-num">2</span>
        <span>Sync Your Account to Local Freeseek</span>
      </div>
      <p>Drag this button up to your browser's Bookmarks bar. While on chat.deepseek.com, click it once to automatically sync your session with this local server:</p>

      <div class="bookmarklet-box">
        <a class="bookmarklet-btn" href="${syncBookmarkletCode}" onclick="showToast('Drag this button to your Bookmarks Bar (press Ctrl+Shift+B if hidden)'); return false;">
          Sync Token with Local Freeseek
        </a>
        <div style="font-size: 12px; color: var(--text-muted); margin-top: 10px;">
          Bookmarks bar hidden? Press <kbd>Ctrl</kbd> + <kbd>Shift</kbd> + <kbd>B</kbd> (or <kbd>Cmd</kbd> + <kbd>Shift</kbd> + <kbd>B</kbd> on Mac).
        </div>
      </div>

      <div style="margin-top: 16px;">
        <span style="font-size: 12.5px; font-weight: 600;">Or enter token manually:</span>
        <div class="input-group">
          <input type="password" id="manual-token" class="input-field" placeholder="Paste userToken here (optional)" />
          <button class="btn btn-primary" onclick="saveManualToken()">Save Token</button>
        </div>
      </div>
    </div>

    <!-- Step 3: Editor Settings -->
    <div class="card">
      <div class="card-title">
        <span class="step-num">3</span>
        <span>Configure Cursor / VS Code / Roo / Continue</span>
      </div>
      <p>In your editor settings, configure an OpenAI-Compatible provider with these values. Notice that the Server (Base URL) and API Parameter (API Key) are two completely separate settings:</p>

      <table class="config-table">
        <tr>
          <td class="config-label">1. Server (Base URL)</td>
          <td><span class="config-val" id="val-baseurl">http://127.0.0.1:${port}/v1</span></td>
          <td style="text-align: right;"><button class="btn-copy" onclick="copyValue('http://127.0.0.1:${port}/v1', this)">Copy Server URL</button></td>
        </tr>
        <tr>
          <td class="config-label">2. API Parameter</td>
          <td><span class="config-val" id="val-apikey">dummy</span></td>
          <td style="text-align: right;"><button class="btn-copy" onclick="copyValue('dummy', this)">Copy API Key</button></td>
        </tr>
        <tr>
          <td class="config-label">3. Model (Reasoning)</td>
          <td><span class="config-val" id="val-model-r1">deepseek-reasoner</span></td>
          <td style="text-align: right;"><button class="btn-copy" onclick="copyValue('deepseek-reasoner', this)">Copy Model</button></td>
        </tr>
        <tr>
          <td class="config-label">4. Model (Chat)</td>
          <td><span class="config-val" id="val-model-v3">deepseek-chat</span></td>
          <td style="text-align: right;"><button class="btn-copy" onclick="copyValue('deepseek-chat', this)">Copy Model</button></td>
        </tr>
      </table>
      <div style="font-size: 12px; color: var(--text-muted); margin-top: 10px;">
        Paste <code>http://127.0.0.1:${port}/v1</code> into the Server / Base URL setting. For the API Key setting, simply enter <code>dummy</code>.
      </div>
    </div>

    <!-- Connection Tester -->
    <div class="card">
      <div class="card-title">
        <span>Test Connection</span>
      </div>
      <p>Test that this local proxy can communicate with DeepSeek using your stored credentials:</p>
      <div style="display: flex; align-items: center; gap: 12px;">
        <button id="test-btn" class="btn btn-outline" onclick="testConnection()">Run Connection Test</button>
        <span id="test-status" style="font-size: 13px; color: var(--text-muted);"></span>
      </div>
    </div>

    <div style="text-align: center; font-size: 12px; color: var(--text-subtle); margin-top: 30px;">
      freeseek - Free Local DeepSeek OpenAI Proxy
    </div>
  </div>

  <div id="toast" class="toast"></div>

  <script>
    async function loadStatus() {
      try {
        const res = await fetch('/api/status');
        const data = await res.json();
        const badge = document.getElementById('status-badge');
        const text = document.getElementById('token-status-text');
        const clearBtn = document.getElementById('clear-btn');

        if (data.hasToken) {
          badge.textContent = 'Connected (' + data.tokenPreview + ')';
          badge.className = 'status-badge connected';
          text.textContent = 'Token saved and active (' + data.tokenPreview + ')';
          clearBtn.style.display = 'inline-block';
        } else {
          badge.textContent = 'Needs Token';
          badge.className = 'status-badge disconnected';
          text.textContent = 'No token saved. Complete Step 1 & 2 above to connect.';
          clearBtn.style.display = 'none';
        }
      } catch (e) {
        document.getElementById('status-badge').textContent = 'Server Offline';
      }
    }

    async function saveManualToken() {
      const input = document.getElementById('manual-token');
      const val = (input.value || '').trim();
      if (!val || val.length < 10) {
        alert('Please enter a valid DeepSeek userToken.');
        return;
      }
      try {
        const res = await fetch('/api/save-token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: val })
        });
        const d = await res.json();
        if (d.success) {
          input.value = '';
          showToast('Token saved successfully! You are ready to use Cursor.');
          loadStatus();
        } else {
          alert('Failed to save token: ' + (d.error || 'Unknown error'));
        }
      } catch (e) {
        alert('Error communicating with local server: ' + e);
      }
    }

    async function disconnectToken() {
      if (!confirm('Disconnect saved DeepSeek token?')) return;
      try {
        await fetch('/api/clear-token', { method: 'POST' });
        showToast('Token disconnected.');
        loadStatus();
      } catch (e) {
        alert('Error: ' + e);
      }
    }

    async function testConnection() {
      const btn = document.getElementById('test-btn');
      const status = document.getElementById('test-status');
      btn.disabled = true;
      status.textContent = 'Testing connection to DeepSeek...';

      try {
        const res = await fetch('/api/test-token', { method: 'POST' });
        const d = await res.json();
        if (d.success) {
          status.style.color = '#000';
          status.textContent = 'Success! Connected to DeepSeek in ' + d.latency + 'ms.';
        } else {
          status.style.color = '#d00';
          status.textContent = 'Connection failed: ' + (d.error || 'Authentication error');
        }
      } catch (e) {
        status.style.color = '#d00';
        status.textContent = 'Test failed: ' + e.message;
      } finally {
        btn.disabled = false;
      }
    }

    function copyValue(text, btn) {
      navigator.clipboard.writeText(text).then(() => {
        const orig = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = orig; }, 1500);
      });
    }

    function showToast(msg) {
      const t = document.getElementById('toast');
      t.textContent = msg;
      t.style.display = 'block';
      setTimeout(() => { t.style.display = 'none'; }, 3000);
    }

    window.addEventListener('DOMContentLoaded', loadStatus);
  </script>
</body>
</html>`);
  });

  const host = process.env.HOST || "0.0.0.0";
  server.listen(port, host, () => {
    const hasToken = !!(getStoredToken() || process.env.DEEPSEEK_AUTH_TOKEN);
    console.log("");
    console.log("============================================================");
    console.log("  freeseek - Local DeepSeek OpenAI Proxy");
    console.log("============================================================");
    console.log("  Dashboard:       http://" + host + ":" + port);
    console.log("  OpenAI Base URL: http://" + host + ":" + port + "/v1");
    console.log("  API Key:         " + (hasToken ? "dummy (token saved locally)" : "Requires DeepSeek Token (open dashboard)"));
    console.log("  Models:          deepseek-reasoner, deepseek-chat");
    console.log("  Stored Config:   " + getConfigFilePath());
    console.log("============================================================");
    console.log("  Press Ctrl+C to stop.");
    console.log("");

    if (process.argv.includes("--open") || process.env.OPEN_BROWSER === "true") {
      openBrowser("http://127.0.0.1:" + port);
    }
  });
}

// CLI Argument Parsing
const args = process.argv.slice(2);
let port = process.env.PORT ? parseInt(process.env.PORT) : 8787;
const portIdx = args.indexOf("--port");
if (portIdx !== -1 && args[portIdx + 1]) {
  port = parseInt(args[portIdx + 1]);
}

startServer(port);
