// https://github.com/fastify/secure-json-parse
// https://github.com/hapijs/bourne
const suspectProtoRx =
  /"(?:_|\\u0{2}5[Ff]){2}(?:p|\\u0{2}70)(?:r|\\u0{2}72)(?:o|\\u0{2}6[Ff])(?:t|\\u0{2}74)(?:o|\\u0{2}6[Ff])(?:_|\\u0{2}5[Ff]){2}"\s*:/;
const suspectConstructorRx =
  /"(?:c|\\u0063)(?:o|\\u006[Ff])(?:n|\\u006[Ee])(?:s|\\u0073)(?:t|\\u0074)(?:r|\\u0072)(?:u|\\u0075)(?:c|\\u0063)(?:t|\\u0074)(?:o|\\u006[Ff])(?:r|\\u0072)"\s*:/;

const JsonSigRx = /^\s*["[{]|^\s*-?\d{1,16}(\.\d{1,17})?([Ee][+-]?\d+)?\s*$/;
const BigIntCandidateRx = /^-?\d{17,}$/;

function jsonParseTransform(key: string, value: any): any {
  if (
    key === "__proto__" ||
    (key === "constructor" &&
      value &&
      typeof value === "object" &&
      "prototype" in value)
  ) {
    warnKeyDropped(key);
    return;
  }
  return value;
}

function warnKeyDropped(key: string): void {
  console.warn(`[destr] Dropping "${key}" key to prevent prototype pollution.`);
}

export type Options = {
  strict?: boolean;
  bigint?: boolean;
};

export function destr<T = unknown>(value: any, options: Options = {}): T {
  if (typeof value !== "string") {
    return value;
  }
  if (
    // eslint-disable-next-line unicorn/prefer-at
    value[0] === '"' &&
    value.at(-1) === '"' &&
    // eslint-disable-next-line unicorn/prefer-includes
    value.indexOf("\\") === -1
  ) {
    return value.slice(1, -1) as T;
  }

  const _value = value.trim();

  if (_value.length <= 9) {
    switch (_value.toLowerCase()) {
      case "true": {
        return true as T;
      }
      case "false": {
        return false as T;
      }
      case "undefined": {
        return undefined as T;
      }
      case "null": {
        // eslint-disable-next-line unicorn/no-null
        return null as T;
      }
      case "nan": {
        return Number.NaN as T;
      }
      case "infinity": {
        return Number.POSITIVE_INFINITY as T;
      }
      case "-infinity": {
        return Number.NEGATIVE_INFINITY as T;
      }
    }
  }

  // Check for potential BigInt (large integers that would lose precision as Number)
  if (options.bigint && BigIntCandidateRx.test(_value)) {
    try {
      return BigInt(_value) as unknown as T;
    } catch (error) {
      if (options.strict) {
        throw error;
      }
      // If it's not a valid BigInt, continue with normal parsing
    }
  }

  if (!JsonSigRx.test(value)) {
    if (options.strict) {
      throw new SyntaxError("[destr] Invalid JSON");
    }
    return value as T;
  }

  try {
    if (suspectProtoRx.test(value) || suspectConstructorRx.test(value)) {
      if (options.strict) {
        throw new Error("[destr] Possible prototype pollution");
      }
      return JSON.parse(value, jsonParseTransform);
    }

    // Parse with or without BigInt support
    if (options.bigint) {
      return JSON.parse(value, (key, val) => {
        // Check if a value is a string that might represent a BigInt
        if (typeof val === "string" && BigIntCandidateRx.test(val)) {
          try {
            return BigInt(val);
          } catch {
            return val;
          }
        }

        // Check if a value is a number that might be better represented as BigInt
        // (for values that might lose precision as Number)
        if (
          typeof val === "number" &&
          !Number.isInteger(val) &&
          Math.abs(val) > Number.MAX_SAFE_INTEGER
        ) {
          try {
            // Try to convert it to a BigInt if it appears to be an integer value
            const strVal = val.toString();
            if (!/[.e]/i.test(strVal)) {
              return BigInt(strVal);
            }
          } catch {
            // If conversion fails, return original value
          }
        }

        return val;
      }) as T;
    }

    return JSON.parse(value);
  } catch (error) {
    if (options.strict) {
      throw error;
    }
    return value as T;
  }
}

export function safeDestr<T = unknown>(value: any, options: Options = {}): T {
  return destr<T>(value, { ...options, strict: true });
}

export default destr;
