/**
 * passmeter WASM 的 JS 封装。
 *
 * 这一层只做三件事：加载实例、管理输入/输出缓冲、把 JSON 解析成对象。
 * 所有评估逻辑都在 Rust 里，JS 不参与任何判断——这样前后端
 * 与服务端的评估结果才可能完全一致。
 *
 * 用法：
 *   const meter = await PassMeter.load('/static/passmeter_wasm.wasm');
 *   const result = meter.evaluate('123qweASD');
 *   result.sequence[0]  // { pattern, start, end, token, guesses, ... }
 */

export class PassMeter {
  static async load(wasmUrl, options = {}) {
    const resp = await fetch(wasmUrl);
    if (!resp.ok) {
      throw new Error(`加载 WASM 失败: ${resp.status} ${wasmUrl}`);
    }
    const bytes = await resp.arrayBuffer();
    return PassMeter.fromBytes(bytes, options);
  }

  static async fromBytes(bytes, options = {}) {
    // 不使用 instantiateStreaming：部分静态服务器不返回 application/wasm，
    // 而且我们需要对同一份字节做体积统计，干脆一次读完。
    const { instance } = await WebAssembly.instantiate(bytes, {});
    const meter = new PassMeter(instance.exports);
    if (!meter.exports.pm_init()) {
      throw new Error(`WASM 初始化失败: ${meter.takeError()}`);
    }
    if (options.tier2Url) {
      await meter.loadTier2(options.tier2Url);
    }
    return meter;
  }

  constructor(exports) {
    this.exports = exports;
    this.encoder = new TextEncoder();
    this.decoder = new TextDecoder('utf-8');
  }

  /** 从 fetch 的结果加载二级词典。失败不抛出：一级词典已足够打分。 */
  async loadTier2(url) {
    try {
      const resp = await fetch(url);
      if (!resp.ok) return false;
      const bytes = new Uint8Array(await resp.arrayBuffer());
      const ptr = this.exports.pm_alloc(bytes.length);
      new Uint8Array(this.exports.memory.buffer, ptr, bytes.length).set(bytes);
      return this.exports.pm_load_tier2(ptr, bytes.length) === 1;
    } catch (e) {
      console.warn('二级词典加载失败，降级为一级词典:', e);
      return false;
    }
  }

  get hasTier2() {
    return this.exports.pm_has_tier2() === 1;
  }

  /**
   * 评估一条口令。
   * @param {string} password
   * @returns {object} 含 score/guesses/sequence/feedback/sha1Prefix 等字段
   */
  evaluate(password) {
    const input = this.encoder.encode(password);
    const ptr = this.exports.pm_alloc(input.length);
    // 注意：pm_alloc 可能触发 memory.grow，必须在分配之后再取 buffer
    new Uint8Array(this.exports.memory.buffer, ptr, input.length).set(input);

    if (!this.exports.pm_eval(ptr, input.length)) {
      throw new Error(`评估失败: ${this.takeError()}`);
    }
    const outPtr = this.exports.pm_result_ptr();
    const outLen = this.exports.pm_result_len();
    const json = this.decoder.decode(
      new Uint8Array(this.exports.memory.buffer, outPtr, outLen)
    );
    this.exports.pm_free_result();
    return JSON.parse(json);
  }

  takeError() {
    const p = this.exports.pm_error_ptr();
    const n = this.exports.pm_error_len();
    if (n === 0) return '(无错误信息)';
    return this.decoder.decode(new Uint8Array(this.exports.memory.buffer, p, n));
  }

  /** 便捷方法：只取哈希前缀，用于 k-匿名泄露查询。 */
  sha1Prefix(password) {
    return this.evaluate(password).sha1Prefix;
  }
}

/**
 * 破解时间的可读表述。与服务端的 timefmt.rs 保持一致的口径，
 * 单位阈值写死成语义常数，避免前后端显示不一致。
 */
export function humanizeSeconds(seconds) {
  if (!isFinite(seconds) || seconds <= 0) return '瞬间';
  const minute = 60, hour = 60 * minute, day = 24 * hour;
  const month = 31 * day, year = 12 * month, century = 100 * year;
  if (seconds < 1) return '不到 1 秒';
  if (seconds < minute) return `${Math.round(seconds)} 秒`;
  if (seconds < hour) return `${Math.round(seconds / minute)} 分钟`;
  if (seconds < day) return `${Math.round(seconds / hour)} 小时`;
  if (seconds < month) return `${Math.round(seconds / day)} 天`;
  if (seconds < year) return `${Math.round(seconds / month)} 个月`;
  if (seconds < century) return `${Math.round(seconds / year)} 年`;
  return '数百年以上';
}
