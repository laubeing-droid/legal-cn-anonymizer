/**
 * legal-cn-anonymizer DSH bundle — Host half（四件套之一：服务 + defineTool +
 * fetch.register；client panel 在 ./client/client.js）。
 *
 * 形状样板 = juscite-engine packages/juscite/{cases,redaction}（服务+defineTool+
 * fetch.register+client panel 四件套）。落点依据：juscite issue #10 Part A
 * 「anonymizer = DSH bundle 形态（模块化铁律 2『独立能力域替换件』正例）」。
 *
 * 能力面（只走公开 CLI，无实现知识——与主仓 M06 AnonymizerEngine 同契约）：
 *   pii_scrub_text     文本脱敏（CLI `scrub - --no-llm --no-critic`，stdin→stdout；
 *                      反向映射 map/report 由 anonymizer 进程直写本侧 vault 目录，
 *                      永不出 anonymizer 侧——安全边界 #2）
 *   pii_rehydrate_text 文本回填（CLI `rehydrate - --map <vault>/<handle>`；
 *                      handle 闭集校验 + vault 目录 containment，拒任意路径读）
 *
 * 宿主兼容（双宿主）：
 *   - Juscite runtime 宿主（runtime/src/host/dsh/，批2-01）：inject 只声明
 *     `tools`（context.ts 服务键闭集无 connection）；
 *   - DSH 生态 Loader：四件套第 3 件 fetch.register 面 = 探测 ctx.connection
 *     可用才挂（Juscite 宿主上访问表外键会具名抛错 → try/catch 具名跳过，
 *     不静默近似）。
 *
 * 诚实边界（NOTICE 同源）：
 *   - --no-llm 口径 = 正则层兜底：姓名等靠 NER 的实体**不保证命中**；NER 权重
 *     （2.7GB）不随包，`ner.qualified=false` 时姓名覆盖 = REVIEW_REQUIRED 人工
 *     复核兜底。永不输出 SAFE / 100% ANONYMIZED。
 *   - 退出码契约（公开文档）：0 ok / 3 degraded / 6 存在未回填假名 / 其余 error。
 *
 * Config（patch 行 config，env 兜底）：
 *   anonymizerRoot  仓根（含 src/legal_anonymizer/__init__.py 预检）
 *                   → env JUSCITE_ANONYMIZER_ROOT
 *   pythonLauncher  "py -3" / "python3" → env JUSCITE_PYTHON_LAUNCHER → 平台缺省
 *   vaultDir        映射 vault 目录 → env JUSCITE_ANONYMIZER_VAULT
 *                   → <homedir>/.legal-cn-anonymizer/dsh-vault
 *   timeoutMs       单次 CLI 超时（缺省 120000）
 *
 * @module @legal-cn-anonymizer/dsh-bundle
 */
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { defineTool } from '@deepseek-ai/dsh-tools';

/** Stable Cordis plugin name; matches the profile patch row id. */
export const name = 'legal-cn-anonymizer';

/** Juscite 宿主服务键闭集只收 tools；connection 面在 apply 内探测（双宿主兼容）。 */
export const inject = ['tools'];

/** 缺省单次 CLI 超时。 */
const DEFAULT_TIMEOUT_MS = 120_000;

/** map 句柄闭集：<jobId>.map.json，jobId = 时间戳36进制+短随机。 */
const MAP_HANDLE_RE = /^[A-Za-z0-9_-]+\.map\.json$/;

const HONEST_NOTICE =
  '正则层离线兜底（--no-llm）：身份证号/手机号/银行卡/邮箱等结构化实体可命中，'
  + '姓名等 NER 实体不保证命中（NER 权重不随包，姓名覆盖=REVIEW_REQUIRED 人工复核兜底）；'
  + '脱敏结果使用前须人工确认。';

function nowJobId() {
  return `dsh-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

/** 解析 anonymizer 仓根（config → env）。 */
function resolveRoot(config) {
  const root = String(config?.anonymizerRoot ?? process.env.JUSCITE_ANONYMIZER_ROOT ?? '').trim();
  if (root === '') return { root: '', configured: false, reason: 'anonymizerRoot 未配置（config 或 JUSCITE_ANONYMIZER_ROOT）' };
  if (!existsSync(join(root, 'src', 'legal_anonymizer', '__init__.py'))) {
    return { root, configured: false, reason: `入口预检失败：${root}/src/legal_anonymizer/__init__.py 不存在` };
  }
  return { root, configured: true };
}

function resolveLauncher(config) {
  return String(config?.pythonLauncher ?? process.env.JUSCITE_PYTHON_LAUNCHER ?? '')
    .trim() || (process.platform === 'win32' ? 'py -3' : 'python3');
}

function resolveVaultDir(config) {
  const dir = String(config?.vaultDir ?? process.env.JUSCITE_ANONYMIZER_VAULT ?? '').trim()
    || join(homedir(), '.legal-cn-anonymizer', 'dsh-vault');
  mkdirSync(dir, { recursive: true });
  return dir;
}

/** map 句柄 → vault 内路径（containment：解析后必须仍在 vaultDir 内）。 */
function mapPathInVault(vaultDir, handle) {
  if (typeof handle !== 'string' || !MAP_HANDLE_RE.test(handle)) {
    throw anonymizerError('mapHandle 形如 <jobId>.map.json（闭集），收到: ' + JSON.stringify(handle ?? null));
  }
  const full = resolve(vaultDir, handle);
  const rootWithSep = resolve(vaultDir).endsWith(sep) ? resolve(vaultDir) : resolve(vaultDir) + sep;
  if (!full.startsWith(rootWithSep)) {
    throw anonymizerError('mapHandle 越界（vault 目录 containment）');
  }
  return full;
}

function anonymizerError(message, status = 400) {
  const error = new Error(message);
  error.anonymizerStatus = status;
  return error;
}

/** 跑一次公开 CLI：stdin 进、stdout 出、超时 kill（只管道、不解释）。 */
function runCli(launcher, args, { root, stdin, timeoutMs }) {
  const [cmd, ...prefix] = launcher.trim().split(/\s+/).filter(Boolean);
  if (!cmd) return Promise.resolve({ code: -1, stdout: '', stderrTail: 'python launcher is empty' });
  return new Promise((resolveDone) => {
    const child = spawn(cmd, [...prefix, ...args], {
      cwd: root,
      env: { ...process.env, PYTHONPATH: join(root, 'src') },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let settled = false;
    const timer = setTimeout(() => {
      try { child.kill(); } catch {}
    }, timeoutMs);
    const settle = (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolveDone({ code, stdout, stderrTail: stderr.slice(-2000).trim() });
    };
    child.stdout.on('data', (d) => { stdout += String(d); });
    child.stderr.on('data', (d) => { stderr += String(d); });
    child.on('error', (err) => { stderr += String(err); settle(-1); });
    child.on('close', (code) => settle(code ?? -1));
    child.stdin.on('error', () => {});
    child.stdin.end(stdin ?? '');
  });
}

/**
 * 服务面：公开 CLI 句柄（scrub/rehydrate 一次一发；映射只落 vault）。
 * 与主仓 M06 AnonymizerEngine 同契约（退出码 0/3/6/其余）。
 */
export function createAnonymizerService(config) {
  const launcher = resolveLauncher(config);
  const timeoutMs = Number(config?.timeoutMs) > 0 ? Number(config.timeoutMs) : DEFAULT_TIMEOUT_MS;

  return {
    status() {
      const r = resolveRoot(config);
      return { configured: r.configured, ...(r.configured ? {} : { reason: r.reason }), launcher, timeoutMs, notice: HONEST_NOTICE };
    },

    async scrub(input = {}) {
      const r = resolveRoot(config);
      if (!r.configured) throw anonymizerError(`脱敏引擎未配置：${r.reason}`, 503);
      if (typeof input?.text !== 'string' || input.text.length === 0) {
        throw anonymizerError('text 必须是非空字符串');
      }
      if (input.text.length > 200_000) throw anonymizerError('文本超过 200000 字符上限，请分段');
      const vaultDir = resolveVaultDir(config);
      const jobId = nowJobId();
      const mapHandle = `${jobId}.map.json`;
      const reportHandle = `${jobId}.report.md`;
      const result = await runCli(launcher, [
        '-m', 'legal_anonymizer', 'scrub', '-',
        '--map', join(vaultDir, mapHandle),
        '--report', join(vaultDir, reportHandle),
        '-o', '-',
        '--policy', 'balanced',
        '--locale', 'zh',
        '--no-llm',
        '--no-critic',
      ], { root: r.root, stdin: input.text, timeoutMs });
      if (result.timedOut) throw anonymizerError(`anonymizer scrub 超时（${timeoutMs}ms）`, 504);
      const status = result.code === 0 ? 'done' : result.code === 3 ? 'degraded' : 'failed';
      return {
        status,
        jobId,
        mapHandle,
        reportHandle,
        exitCode: result.code,
        ...(status === 'failed' ? { error: result.stderrTail || `anonymizer scrub exited ${result.code}` } : {}),
        ...(result.code === 3 ? { error: result.stderrTail || 'degraded: a requested protection layer did not run' } : {}),
        sanitizedText: result.stdout,
        notice: HONEST_NOTICE,
      };
    },

    async rehydrate(input = {}) {
      const r = resolveRoot(config);
      if (!r.configured) throw anonymizerError(`脱敏引擎未配置：${r.reason}`, 503);
      if (typeof input?.text !== 'string' || input.text.length === 0) {
        throw anonymizerError('text 必须是非空字符串');
      }
      const vaultDir = resolveVaultDir(config);
      const mapPath = mapPathInVault(vaultDir, input?.mapHandle);
      const result = await runCli(launcher, [
        '-m', 'legal_anonymizer', 'rehydrate', '-',
        '--map', mapPath,
        '-o', '-',
      ], { root: r.root, stdin: input.text, timeoutMs });
      if (result.timedOut) throw anonymizerError(`anonymizer rehydrate 超时（${timeoutMs}ms）`, 504);
      const status = result.code === 0 ? 'done' : result.code === 6 ? 'partial' : 'failed';
      return {
        status,
        exitCode: result.code,
        restoredText: result.stdout,
        ...(result.code === 6 ? { error: result.stderrTail || '存在未回填假名（映射不完整）' } : {}),
        ...(status === 'failed' ? { error: result.stderrTail || `anonymizer rehydrate exited ${result.code}` } : {}),
      };
    },
  };
}

/**
 * 注册插件：tools 两件 +（探测到 connection 才挂的）HTTP API 三件。
 * @param {object} ctx - 宿主插件面（Juscite face / DSH cordis context）。
 * @param {{ anonymizerRoot?: string, pythonLauncher?: string, vaultDir?: string, timeoutMs?: number }} [config]
 */
export function apply(ctx, config) {
  const service = createAnonymizerService(config);

  // ---- defineTool（四件套之二）-------------------------------------------------
  ctx.tools.register(defineTool({
    name: 'pii_scrub_text',
    description:
      '对一段文本做**本地脱敏**（legal-cn-anonymizer 正则层离线兜底）：身份证号/手机号/银行卡/邮箱等'
      + '结构化实体替换为假名，反向映射保存在本机 vault（永不出本仓）。注意：姓名等 NER 实体不保证命中'
      + '（NER 权重不随包，姓名覆盖=REVIEW_REQUIRED 人工复核兜底）；本工具只处理传入文本，不拦截模型请求；'
      + '脱敏结果使用前请人工确认。回填用 pii_rehydrate_text + 返回的 mapHandle。',
    parameters: {
      text: { type: 'string', required: true, description: '要脱敏的文本（上限 200000 字符）.' },
    },
    execute(args) {
      return service.scrub({ text: args?.text });
    },
  }));

  ctx.tools.register(defineTool({
    name: 'pii_rehydrate_text',
    description:
      '用之前 pii_scrub_text 产出的映射（mapHandle）把假名文本回填为真实文本。mapHandle 来自'
      + ' pii_scrub_text 的返回值。映射只在本机 vault 中查找。',
    parameters: {
      text: { type: 'string', required: true, description: '含假名的文本.' },
      mapHandle: { type: 'string', required: true, description: 'pii_scrub_text 返回的 mapHandle（<jobId>.map.json）.' },
    },
    execute(args) {
      return service.rehydrate({ text: args?.text, mapHandle: args?.mapHandle });
    },
  }));

  // ---- fetch.register（四件套之三；双宿主探测）--------------------------------
  let connection;
  try {
    connection = ctx.connection;
  } catch {
    connection = undefined; // Juscite 宿主：表外服务键访问具名抛错 → 同名跳过
  }
  if (connection && typeof connection.fetch?.register === 'function') {
    const json = (body, status = 200) => new Response(JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
    });
    const apiRoute = (path, methods, handler) => ctx.effect(
      () => connection.fetch.register({
        path: `/api/legal-cn-anonymizer${path}`,
        methods,
        requestBody: 'buffered',
        fetch: async (request) => {
          try {
            return await handler(request);
          } catch (error) {
            const status = Number(error?.anonymizerStatus) || 400;
            return json({ ok: false, error: error instanceof Error ? error.message : String(error) }, status);
          }
        },
      }),
      `legal-cn-anonymizer: /api/legal-cn-anonymizer${path}`,
    );
    apiRoute('/state', ['GET', 'HEAD'], async () => json({ ok: true, ...service.status() }));
    apiRoute('/scrub', ['POST'], async (request) => {
      const body = (await request.json()) ?? {};
      return json({ ok: true, ...await service.scrub(body) });
    });
    apiRoute('/rehydrate', ['POST'], async (request) => {
      const body = (await request.json()) ?? {};
      return json({ ok: true, ...await service.rehydrate(body) });
    });
  }
}
